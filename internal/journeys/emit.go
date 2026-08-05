package journeys

import (
	"fmt"
	"strconv"
	"strings"
)

// This file is the recorder's compiler: it turns a captured stream of user input
// events into a Journey document. It is deliberately pure — it holds no Windows or
// hook types, only the neutral Event vocabulary the OS-side recorder produces — so
// the coalescing and, crucially, the redaction are unit-testable without a desktop.
//
// The recorder is the primary author of a journey: nobody hand-writes forty steps
// of JSON. So this file does more than transcribe. It infers the verb from what
// was clicked, and picks the most stable selector the element offers, because the
// moment of capture is the only moment at which either can be decided with the
// element and its tree both in hand.

// EventKind is the class of a captured input event.
type EventKind string

const (
	// EventClick is a mouse click resolved to a UI element (or bare coordinates).
	EventClick EventKind = "click"
	// EventChar is one typed character. Consecutive chars coalesce into a type_text.
	EventChar EventKind = "char"
	// EventKey is a non-text key press (Enter, Tab, Escape, …) that does not
	// coalesce into typed text.
	EventKey EventKind = "key"
)

// Event is one captured user action. The OS-side recorder fills the fields
// relevant to its Kind; the emitter reads only those.
type Event struct {
	Kind EventKind

	// Click fields.
	X, Y int // physical-pixel screen coordinates of the click
	// AutomationID is the developer-assigned id of the clicked element, when the
	// application sets one. It is the top rung of the selector ladder: unlike the
	// accessible name it survives translation.
	AutomationID string
	Name         string // resolved accessible name of the clicked element ("" if none)
	ControlType  string // e.g. Button, Edit, ListItem
	Button       string // left | right | middle (default left)
	Double       bool   // a double-click

	// Char fields.
	Char rune // the typed rune
	// Secure marks a keystroke into a password-class field. Secure runs are
	// redacted: their characters are never written to the journey. This is the
	// recorder's one security-critical signal, pinned by a never-contains-secret test.
	Secure bool

	// Key fields.
	Key string // the named key: "Enter", "Tab", "Escape", "Backspace", …
}

// RedactedPlaceholder is the step name used where a secure typed run was dropped.
// The step is emitted as an enter_credential carrying no credential name, so the
// captured keystrokes never reach the file and the draft says what to supply
// instead — a stored credential the agent can use but never read.
const RedactedPlaceholder = "sign in (redacted — name the stored credential before running)"

// Emit compiles a captured event stream into a Journey. Consecutive typed
// characters coalesce into one type_text step; a secure run becomes a single
// enter_credential step carrying no secret. Clicks become the verb their control
// type implies, targeting the element by the most stable key it offers. A named
// key becomes press_keys, except a trailing Enter, which folds into the preceding
// text step as submit.
//
// The result is a reviewable draft: the recorder captures actions, not intent, so
// the human who recorded it confirms the steps and adds the assertions that make
// it a test.
func Emit(name string, events []Event) Journey {
	j := Journey{
		Version:     SchemaVersion,
		Name:        name,
		Description: "Recorded journey — review the steps and add assertions before use.",
	}

	var (
		run     []rune    // buffered non-secure typed characters (empty for a secure run)
		pending bool      // a typed run is being built
		secure  bool      // the pending run is into a password-class field
		focused *Selector // the last clicked element, which is what typing goes into
	)

	flush := func(submit bool) {
		if !pending {
			return
		}
		j.Steps = append(j.Steps, textStep(string(run), secure, submit, focused))
		run, pending, secure = nil, false, false
	}

	for _, e := range events {
		switch e.Kind {
		case EventChar:
			// A change in the secure flag ends the current run: a redacted run and a
			// visible run must never merge into one step, or a password character
			// could be carried out on a visible text step.
			if pending && e.Secure != secure {
				flush(false)
			}
			pending, secure = true, e.Secure
			if !e.Secure {
				run = append(run, e.Char) // a secure run records no characters
			}
		case EventKey:
			if e.Key == "Enter" && pending {
				flush(true) // fold a trailing Enter into the text step being built
				continue
			}
			flush(false)
			j.Steps = append(j.Steps, Step{
				Name: "press " + e.Key,
				Verb: VerbPressKeys,
				Keys: e.Key,
			})
		case EventClick:
			flush(false)
			step := clickStep(e)
			focused = step.Target
			j.Steps = append(j.Steps, step)
		}
	}
	flush(false)
	return j
}

// clickStep builds the step for one click: the verb its control type implies,
// targeting the element by the highest rung of the selector ladder it offers.
func clickStep(e Event) Step {
	sel := selectorFor(e)
	verb := clickVerb(e)
	return Step{
		Name:   fmt.Sprintf("%s %s", verb, strconv.Quote(sel.Label())),
		Verb:   verb,
		Target: sel,
	}
}

// clickVerb infers what a click meant from the control type. A double or
// non-left click is taken at face value — those are gestures, not patterns.
//
// The fallback is deliberately `click`: a general verb is recoverable, a wrong
// verb changes what the run does. Reading the element's supported UIA patterns
// would sharpen this — a Button that exposes no Invoke pattern is really a click —
// and is the refinement the capture path is missing.
func clickVerb(e Event) Verb {
	switch {
	case e.Double:
		return VerbDoubleClick
	case e.Button == "right":
		return VerbRightClick
	case e.Name == "" && e.AutomationID == "":
		return VerbClick // a coordinate target cannot be pattern-driven
	}
	switch e.ControlType {
	case "CheckBox", "RadioButton":
		return VerbToggle
	case "ListItem", "TreeItem", "TabItem", "DataItem":
		return VerbSelect
	case "Button", "SplitButton", "Hyperlink", "MenuItem":
		return VerbInvoke
	default:
		return VerbClick
	}
}

// selectorFor picks the most stable selector the clicked element offers:
// automation id, then accessible name, then the raw coordinate.
func selectorFor(e Event) *Selector {
	switch {
	case strings.TrimSpace(e.AutomationID) != "":
		sel := &Selector{AutomationID: e.AutomationID}
		if e.ControlType != "" {
			sel.ControlType = e.ControlType
		}
		return sel
	case strings.TrimSpace(e.Name) != "":
		sel := &Selector{Name: e.Name}
		if e.ControlType != "" {
			sel.ControlType = e.ControlType
		}
		return sel
	default:
		return &Selector{Point: []int{e.X, e.Y}}
	}
}

// textStep builds the step for a typed run: a type_text, or — where the run went
// into a password-class field — an enter_credential carrying no secret.
//
// The redacted step names no credential on purpose. It does not validate, so
// `journey validate` refuses the draft with a message saying what to supply,
// rather than the draft running and typing nothing into a sign-in form.
func textStep(text string, secure, submit bool, focused *Selector) Step {
	if secure {
		return Step{
			Name:   RedactedPlaceholder,
			Verb:   VerbEnterCredential,
			Target: focused,
			Submit: submit,
		}
	}
	return Step{
		Name:   "type " + shorten(text),
		Verb:   VerbTypeText,
		Target: focused,
		Text:   text,
		Submit: submit,
	}
}

// shorten renders a compact label for a typed run.
func shorten(text string) string {
	text = strings.ReplaceAll(text, "\n", " ")
	if len(text) > 24 {
		return "\"" + text[:24] + "…\""
	}
	return "\"" + text + "\""
}
