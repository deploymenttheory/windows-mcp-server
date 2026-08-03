package journeys

import (
	"fmt"
	"strings"
)

// This file is the recorder's compiler: it turns a captured stream of user input
// events into a Journey document. It is deliberately pure — it holds no Windows or
// hook types, only the neutral Event vocabulary the OS-side recorder produces — so
// the coalescing and, crucially, the redaction are unit-testable without a desktop.

// EventKind is the class of a captured input event.
type EventKind string

const (
	// EventClick is a mouse click resolved to a UI element (or bare coordinates).
	EventClick EventKind = "click"
	// EventChar is one typed character. Consecutive chars coalesce into a Type step.
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
	X, Y        int    // physical-pixel screen coordinates of the click
	Name        string // resolved accessible name of the clicked element ("" if none)
	ControlType string // e.g. Button, Edit, ListItem
	Button      string // left | right | middle (default left)
	Double      bool   // a double-click

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
// The step is emitted with empty text so the journey stays runnable — a human
// fills in the secret before running it — while the captured keystrokes never
// reach the file.
const RedactedPlaceholder = "type into a password field (redacted — fill in before running)"

// Emit compiles a captured event stream into a Journey. Consecutive typed
// characters coalesce into one Type step; a secure run becomes a single redacted
// Type step carrying no text. Clicks become Click steps targeting the element by
// accessible name (falling back to coordinates when it has none). A named key
// becomes a Shortcut step, except a trailing Enter, which folds into the preceding
// Type step as press_enter.
//
// The result is a reviewable draft: the human who recorded it confirms or edits
// the steps and adds assertions before checking it in.
func Emit(name string, events []Event) Journey {
	j := Journey{
		Version:     SchemaVersion,
		Name:        name,
		Description: "Recorded journey — review the steps and add assertions before use.",
	}

	var (
		run     []rune // buffered non-secure typed characters (empty for a secure run)
		pending bool   // a typed run is being built
		secure  bool   // the pending run is into a password-class field
	)

	flush := func() {
		if !pending {
			return
		}
		j.Steps = append(j.Steps, typeStep(string(run), secure))
		run, pending, secure = nil, false, false
	}

	for _, e := range events {
		switch e.Kind {
		case EventChar:
			// A change in the secure flag ends the current run: a redacted run and a
			// visible run must never merge into one step, or a password character
			// could be carried out on a visible Type step.
			if pending && e.Secure != secure {
				flush()
			}
			pending, secure = true, e.Secure
			if !e.Secure {
				run = append(run, e.Char) // a secure run records no characters
			}
		case EventKey:
			if e.Key == "Enter" && pending {
				// Fold a trailing Enter into the text step being built.
				j.Steps = append(j.Steps, typeStepWithEnter(string(run), secure))
				run, pending, secure = nil, false, false
				continue
			}
			flush()
			j.Steps = append(j.Steps, shortcutStep(e.Key))
		case EventClick:
			flush()
			j.Steps = append(j.Steps, clickStep(e))
		}
	}
	flush()
	return j
}

// clickStep builds a Click step. It targets the element by accessible name when it
// has one — durable across coordinate changes — and falls back to raw coordinates
// only when the element is unnamed.
func clickStep(e Event) Step {
	args := map[string]any{}
	var label string
	if strings.TrimSpace(e.Name) != "" {
		args["name"] = e.Name
		if e.ControlType != "" {
			args["control_type"] = e.ControlType
		}
		label = "click " + e.Name
	} else {
		args["loc"] = []any{e.X, e.Y}
		label = fmt.Sprintf("click at (%d,%d)", e.X, e.Y)
	}
	if e.Button != "" && e.Button != "left" {
		args["button"] = e.Button
	}
	if e.Double {
		args["clicks"] = 2
	}
	return Step{Name: label, Tool: "Click", Args: args}
}

// typeStep builds a Type step, redacting a secure run to empty text.
func typeStep(text string, secure bool) Step {
	if secure {
		return Step{Name: RedactedPlaceholder, Tool: "Type", Args: map[string]any{"text": ""}}
	}
	return Step{Name: "type " + shorten(text), Tool: "Type", Args: map[string]any{"text": text}}
}

// typeStepWithEnter is typeStep plus press_enter, for a run terminated by Enter.
func typeStepWithEnter(text string, secure bool) Step {
	s := typeStep(text, secure)
	s.Args["press_enter"] = true
	return s
}

// shortcutStep builds a Shortcut step for a named key.
func shortcutStep(key string) Step {
	return Step{Name: "press " + key, Tool: "Shortcut", Args: map[string]any{"shortcut": key}}
}

// shorten renders a compact label for a typed run.
func shorten(text string) string {
	text = strings.ReplaceAll(text, "\n", " ")
	if len(text) > 24 {
		return "\"" + text[:24] + "…\""
	}
	return "\"" + text + "\""
}
