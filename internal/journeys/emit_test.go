package journeys

import (
	"encoding/json"
	"strings"
	"testing"
)

// chars is a helper turning a string into a run of char events.
func chars(s string, secure bool) []Event {
	var out []Event
	for _, r := range s {
		out = append(out, Event{Kind: EventChar, Char: r, Secure: secure})
	}
	return out
}

func TestEmitCoalescesTypedRuns(t *testing.T) {
	events := append(chars("hello", false), Event{Kind: EventClick, Name: "Submit", ControlType: "Button"})
	j := Emit("login", events)

	if j.Name != "login" || j.Version != SchemaVersion {
		t.Fatalf("unexpected header: %+v", j)
	}
	if len(j.Steps) != 2 {
		t.Fatalf("want a Type then a Click, got %d steps: %+v", len(j.Steps), j.Steps)
	}
	if j.Steps[0].Tool != "Type" || j.Steps[0].Args["text"] != "hello" {
		t.Errorf("first step should type the coalesced run, got %+v", j.Steps[0])
	}
	if j.Steps[1].Tool != "Click" || j.Steps[1].Args["name"] != "Submit" {
		t.Errorf("second step should click the named element, got %+v", j.Steps[1])
	}
	if j.Steps[1].Args["control_type"] != "Button" {
		t.Errorf("click should carry the control type, got %+v", j.Steps[1].Args)
	}
}

func TestEmitClickFallsBackToCoordinates(t *testing.T) {
	j := Emit("x", []Event{{Kind: EventClick, X: 10, Y: 20}})
	if len(j.Steps) != 1 {
		t.Fatalf("want one step, got %d", len(j.Steps))
	}
	loc, ok := j.Steps[0].Args["loc"].([]any)
	if !ok || len(loc) != 2 || loc[0] != 10 || loc[1] != 20 {
		t.Errorf("an unnamed click should fall back to coordinates, got %+v", j.Steps[0].Args)
	}
	if _, named := j.Steps[0].Args["name"]; named {
		t.Error("an unnamed click must not carry a name")
	}
}

func TestEmitFoldsTrailingEnterIntoType(t *testing.T) {
	events := append(chars("query", false), Event{Kind: EventKey, Key: "Enter"})
	j := Emit("search", events)
	if len(j.Steps) != 1 {
		t.Fatalf("Enter should fold into the Type step, got %d steps", len(j.Steps))
	}
	if j.Steps[0].Tool != "Type" || j.Steps[0].Args["press_enter"] != true {
		t.Errorf("want a Type with press_enter, got %+v", j.Steps[0])
	}
}

func TestEmitNonTextKeyBecomesShortcut(t *testing.T) {
	j := Emit("x", []Event{{Kind: EventKey, Key: "Tab"}})
	if len(j.Steps) != 1 || j.Steps[0].Tool != "Shortcut" || j.Steps[0].Args["shortcut"] != "Tab" {
		t.Fatalf("a bare Tab should be a Shortcut, got %+v", j.Steps)
	}
}

// TestEmitNeverWritesSecretKeystrokes is the security-critical test: characters
// typed into a password-class field must never appear anywhere in the emitted
// journey — not as text, not in a step name, nowhere in the serialized document.
func TestEmitNeverWritesSecretKeystrokes(t *testing.T) {
	const secret = "hunter2SUPERSECRET"
	events := []Event{
		{Kind: EventClick, Name: "Username", ControlType: "Edit"},
	}
	events = append(events, chars("alice", false)...)
	events = append(events, Event{Kind: EventClick, Name: "Password", ControlType: "Edit"})
	events = append(events, chars(secret, true)...) // secure run
	events = append(events, Event{Kind: EventClick, Name: "Sign in", ControlType: "Button"})

	j := Emit("sign-in", events)

	blob, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), secret) {
		t.Fatalf("the emitted journey must never contain the secret keystrokes:\n%s", blob)
	}
	if strings.Contains(string(blob), "hunter2") {
		t.Fatal("no fragment of the secret may survive")
	}

	// The visible username must survive; only the secure run is dropped.
	if !strings.Contains(string(blob), "alice") {
		t.Error("non-secure typed text should be preserved")
	}
	// There must still be a placeholder Type step where the password went, so the
	// journey stays runnable and a human knows to fill it in.
	var redacted bool
	for _, s := range j.Steps {
		if s.Tool == "Type" && s.Name == RedactedPlaceholder {
			redacted = true
			if s.Args["text"] != "" {
				t.Errorf("the redacted step must carry empty text, got %q", s.Args["text"])
			}
		}
	}
	if !redacted {
		t.Error("a redacted placeholder step should mark where the password was typed")
	}
}

// TestEmitSplitsSecureAndVisibleRuns checks a secure run adjacent to a visible run
// does not merge, so a password cannot ride out on a visible step.
func TestEmitSplitsSecureAndVisibleRuns(t *testing.T) {
	events := append(chars("ab", false), chars("XY", true)...)
	events = append(events, chars("cd", false)...)
	j := Emit("x", events)

	if len(j.Steps) != 3 {
		t.Fatalf("want visible/redacted/visible = 3 steps, got %d: %+v", len(j.Steps), j.Steps)
	}
	if j.Steps[0].Args["text"] != "ab" || j.Steps[2].Args["text"] != "cd" {
		t.Errorf("visible runs should be preserved on both sides, got %+v", j.Steps)
	}
	if j.Steps[1].Name != RedactedPlaceholder || j.Steps[1].Args["text"] != "" {
		t.Errorf("the middle run should be a redacted placeholder, got %+v", j.Steps[1])
	}
}

// TestEmittedJourneyValidatesAndCompiles: a recorded draft must be a real journey —
// it parses, validates and compiles like a hand-written one.
func TestEmittedJourneyValidatesAndCompiles(t *testing.T) {
	events := append(chars("hi", false), Event{Kind: EventClick, Name: "OK", ControlType: "Button"})
	j := Emit("smoke", events)
	if err := j.Validate(); err != nil {
		t.Fatalf("an emitted journey should validate: %v", err)
	}
	if _, err := Compile(j, "sess"); err != nil {
		t.Fatalf("an emitted journey should compile: %v", err)
	}
}
