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
	// EventAssert is the author pointing at something and saying it matters. It
	// carries no action: it becomes an assertion on the step being recorded.
	EventAssert EventKind = "assert"
)

// ElementFacts is what the accessibility tree reported about an element at the
// moment of capture: which patterns it supports, and what they currently hold.
//
// Pattern availability is the difference between recording what was clicked and
// recording what the click meant. A checkbox and a button look the same to a
// mouse hook; only the tree knows one has a toggle state.
type ElementFacts struct {
	Value    string
	Checked  bool
	Selected bool
	Enabled  bool
	Expanded bool

	HasValue          bool
	HasToggle         bool
	HasSelection      bool
	HasInvoke         bool
	HasExpandCollapse bool
}

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
	// Facts is what the element could do and held at capture time. Empty when the
	// tree reported nothing, in which case inference falls back to the control type.
	Facts ElementFacts

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
		case EventAssert:
			flush(false)
			j.Steps = attachAssertion(j.Steps, e)
		}
	}
	flush(false)
	return j
}

// attachAssertion hangs a marked assertion on the step being recorded.
//
// A mark with no preceding step gets an observe to hang from: the assertion is
// still what the author meant, and an observe is the verb for "look at the screen
// and check something" without performing an action.
func attachAssertion(steps []Step, e Event) []Step {
	as, ok := proposeAssertion(e)
	if !ok {
		return steps
	}
	if len(steps) == 0 {
		steps = append(steps, Step{Name: "check the starting state", Verb: VerbObserve})
	}
	last := len(steps) - 1
	steps[last].Assertions = append(steps[last].Assertions, as)
	return steps
}

// proposeAssertion turns what the tree reported about the marked element into the
// assertion the author most likely meant, with the observed value as the expected
// one. It is a proposal: the recorder captures actions, not intent, and this is a
// draft for a human to confirm — but confirming a filled-in comparison is a
// different job from writing one.
func proposeAssertion(e Event) (Assertion, bool) {
	sel := selectorFor(e)
	if sel == nil {
		return Assertion{}, false
	}
	f := e.Facts
	switch {
	case f.HasValue && f.Value != "":
		return Assertion{
			Subject: SubjectElementValue, Target: sel, Operator: OpIs, Expected: f.Value,
			Message: fmt.Sprintf("%s still reads %q", sel.Label(), f.Value),
		}, true
	case f.HasToggle:
		return Assertion{
			Subject: SubjectElementChecked, Target: sel, Operator: boolOperator(f.Checked),
			Message: fmt.Sprintf("%s is %s", sel.Label(), checkedWord(f.Checked)),
		}, true
	case f.HasSelection:
		return Assertion{
			Subject: SubjectElementSelected, Target: sel, Operator: boolOperator(f.Selected),
			Message: fmt.Sprintf("%s is %s", sel.Label(), selectedWord(f.Selected)),
		}, true
	case sel.AutomationID != "" && strings.TrimSpace(e.Name) != "":
		// Targeted by id, so asserting the name is a real check rather than a
		// restatement of the selector — and a renamed control is exactly the
		// regression an id-targeted suite would otherwise sail past.
		return Assertion{
			Subject: SubjectElementName, Target: sel, Operator: OpIs, Expected: e.Name,
			Message: fmt.Sprintf("%s is still labelled %q", sel.AutomationID, e.Name),
		}, true
	default:
		return Assertion{
			Subject: SubjectElement, Target: sel, Operator: OpExists,
			Message: fmt.Sprintf("%s is present", sel.Label()),
		}, true
	}
}

func boolOperator(v bool) Operator {
	if v {
		return OpIsTrue
	}
	return OpIsFalse
}

func checkedWord(v bool) string {
	if v {
		return "checked"
	}
	return "unchecked"
}

func selectedWord(v bool) string {
	if v {
		return "selected"
	}
	return "not selected"
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

// clickVerb infers what a click meant. A double or non-left click is taken at
// face value — those are gestures, not patterns.
//
// Otherwise the element's supported UIA patterns decide, because they say what
// the control can actually do: a checkbox and a button are the same event to a
// mouse hook, and only the tree knows one has a toggle state. The order is by
// specificity — a combo box supports both ExpandCollapse and Value, and clicking
// it opens it.
//
// The control type is the fallback for a tree that reports no patterns, and
// `click` the fallback below that. A general verb is recoverable; a wrong verb
// changes what the run does.
func clickVerb(e Event) Verb {
	switch {
	case e.Double:
		return VerbDoubleClick
	case e.Button == "right":
		return VerbRightClick
	case e.Name == "" && e.AutomationID == "":
		return VerbClick // a coordinate target cannot be pattern-driven
	}

	switch f := e.Facts; {
	case f.HasToggle:
		return VerbToggle
	case f.HasSelection:
		return VerbSelect
	case f.HasExpandCollapse:
		// Read the direction from where the control currently is, not from the
		// click: recording expand for an already-open node produces a step that
		// closes it on the next run.
		if f.Expanded {
			return VerbCollapse
		}
		return VerbExpand
	case f.HasInvoke:
		return VerbInvoke
	case f.HasValue:
		// A text field. The click focused it for the typing that follows, and
		// recording that as invoke would activate rather than focus it.
		return VerbClick
	}
	return verbFromControlType(e.ControlType)
}

// verbFromControlType is the fallback when the tree reported no patterns at all,
// which happens with older frameworks and some custom controls.
func verbFromControlType(controlType string) Verb {
	switch controlType {
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
