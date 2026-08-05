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
		t.Fatalf("want a type_text then a click, got %d steps: %+v", len(j.Steps), j.Steps)
	}
	if j.Steps[0].Verb != VerbTypeText || j.Steps[0].Text != "hello" {
		t.Errorf("first step should type the coalesced run, got %+v", j.Steps[0])
	}
	if j.Steps[1].Target.Name != "Submit" || j.Steps[1].Target.ControlType != "Button" {
		t.Errorf("second step should target the named element, got %+v", j.Steps[1].Target)
	}
}

// TestEmitInfersTheVerbFromTheControlType: a click is not a verb. Recording every
// one of them as `click` throws away what the tree already knows and drives the UI
// through synthetic input where a pattern was available.
func TestEmitInfersTheVerbFromTheControlType(t *testing.T) {
	cases := map[string]struct {
		event Event
		want  Verb
	}{
		"button":       {Event{Kind: EventClick, Name: "OK", ControlType: "Button"}, VerbInvoke},
		"checkbox":     {Event{Kind: EventClick, Name: "Remember me", ControlType: "CheckBox"}, VerbToggle},
		"radio":        {Event{Kind: EventClick, Name: "Monthly", ControlType: "RadioButton"}, VerbToggle},
		"list item":    {Event{Kind: EventClick, Name: "Row 3", ControlType: "ListItem"}, VerbSelect},
		"tab":          {Event{Kind: EventClick, Name: "Details", ControlType: "TabItem"}, VerbSelect},
		"edit field":   {Event{Kind: EventClick, Name: "Amount", ControlType: "Edit"}, VerbClick},
		"double click": {Event{Kind: EventClick, Name: "File", ControlType: "ListItem", Double: true}, VerbDoubleClick},
		"right click":  {Event{Kind: EventClick, Name: "File", ControlType: "ListItem", Button: "right"}, VerbRightClick},
		"unnamed":      {Event{Kind: EventClick, X: 10, Y: 20}, VerbClick},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			j := Emit("x", []Event{tc.event})
			if got := j.Steps[0].Verb; got != tc.want {
				t.Errorf("verb = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestVerbComesFromPatternsBeforeControlType: a checkbox and a button are the
// same event to a mouse hook, and only the accessibility tree knows one has a
// toggle state. Where the two disagree, the pattern wins — it says what the
// control can actually do, and the control type is only a label.
func TestVerbComesFromPatternsBeforeControlType(t *testing.T) {
	cases := map[string]struct {
		event Event
		want  Verb
	}{
		"toggle beats a Button control type": {
			Event{Kind: EventClick, Name: "Bold", ControlType: "Button",
				Facts: ElementFacts{HasToggle: true}}, VerbToggle,
		},
		"selection item": {
			Event{Kind: EventClick, Name: "Row 3", ControlType: "Custom",
				Facts: ElementFacts{HasSelection: true, HasInvoke: true}}, VerbSelect,
		},
		"a closed expander expands": {
			Event{Kind: EventClick, Name: "Advanced", ControlType: "Custom",
				Facts: ElementFacts{HasExpandCollapse: true, HasValue: true}}, VerbExpand,
		},
		"an open expander collapses": {
			Event{Kind: EventClick, Name: "Advanced", ControlType: "Custom",
				Facts: ElementFacts{HasExpandCollapse: true, Expanded: true}}, VerbCollapse,
		},
		"invoke": {
			Event{Kind: EventClick, Name: "Submit", ControlType: "Custom",
				Facts: ElementFacts{HasInvoke: true}}, VerbInvoke,
		},
		"a text field is focused, not invoked": {
			Event{Kind: EventClick, Name: "Amount", ControlType: "Edit",
				Facts: ElementFacts{HasValue: true}}, VerbClick,
		},
		"no patterns falls back to the control type": {
			Event{Kind: EventClick, Name: "OK", ControlType: "Button"}, VerbInvoke,
		},
		"no patterns and no useful control type": {
			Event{Kind: EventClick, Name: "Thing", ControlType: "Custom"}, VerbClick,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := Emit("x", []Event{tc.event}).Steps[0].Verb; got != tc.want {
				t.Errorf("verb = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestMarkedAssertionsAttachToTheStepBeingRecorded is the answer to "a recording
// captures actions, not intent". Pointing at what matters and pressing the key is
// the cheapest moment to say so, because it is the moment the author is looking
// at it.
func TestMarkedAssertionsAttachToTheStepBeingRecorded(t *testing.T) {
	j := Emit("x", []Event{
		{Kind: EventClick, AutomationID: "btnCalc", Facts: ElementFacts{HasInvoke: true}},
		{
			Kind: EventAssert, AutomationID: "lblTotal", Name: "Total",
			Facts: ElementFacts{HasValue: true, Value: "£126.40"},
		},
	})

	if len(j.Steps) != 1 {
		t.Fatalf("a mark carries no action, so it should add no step: %+v", j.Steps)
	}
	if len(j.Steps[0].Assertions) != 1 {
		t.Fatalf("the mark should become an assertion on the click: %+v", j.Steps[0])
	}
	as := j.Steps[0].Assertions[0]
	if as.Subject != SubjectElementValue || as.Operator != OpIs || as.Expected != "£126.40" {
		t.Errorf("the observed value should become the expected one: %+v", as)
	}
	if as.Target.AutomationID != "lblTotal" {
		t.Errorf("the assertion should target what was pointed at: %+v", as.Target)
	}
	if err := j.Validate(); err != nil {
		t.Errorf("a marked draft should validate: %v", err)
	}
}

// TestProposedAssertionMatchesWhatTheElementExposes: the proposal is only useful
// if it asserts something the control actually has.
func TestProposedAssertionMatchesWhatTheElementExposes(t *testing.T) {
	cases := map[string]struct {
		event    Event
		subject  Subject
		operator Operator
	}{
		"a value field": {
			Event{Kind: EventAssert, Name: "Total", Facts: ElementFacts{HasValue: true, Value: "9"}},
			SubjectElementValue, OpIs,
		},
		"a ticked checkbox": {
			Event{Kind: EventAssert, Name: "Agree", Facts: ElementFacts{HasToggle: true, Checked: true}},
			SubjectElementChecked, OpIsTrue,
		},
		"an unticked checkbox": {
			Event{Kind: EventAssert, Name: "Agree", Facts: ElementFacts{HasToggle: true}},
			SubjectElementChecked, OpIsFalse,
		},
		"a selected row": {
			Event{Kind: EventAssert, Name: "Row", Facts: ElementFacts{HasSelection: true, Selected: true}},
			SubjectElementSelected, OpIsTrue,
		},
		"an empty value field falls through to existence": {
			Event{Kind: EventAssert, Name: "Notes", Facts: ElementFacts{HasValue: true}},
			SubjectElement, OpExists,
		},
		"a plain element": {
			Event{Kind: EventAssert, Name: "Heading"},
			SubjectElement, OpExists,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			as, ok := proposeAssertion(tc.event)
			if !ok {
				t.Fatal("want a proposal")
			}
			if as.Subject != tc.subject || as.Operator != tc.operator {
				t.Errorf("proposed %s %s, want %s %s", as.Subject, as.Operator, tc.subject, tc.operator)
			}
			if as.Message == "" {
				t.Error("a proposal should say what it is checking, for the human reading the draft")
			}
		})
	}
}

// TestIDTargetedMarkAssertsTheName: when the selector is an automation id,
// asserting the name is a real check rather than a restatement of the selector —
// and a renamed control is exactly the regression an id-targeted suite would
// otherwise sail past.
func TestIDTargetedMarkAssertsTheName(t *testing.T) {
	as, ok := proposeAssertion(Event{Kind: EventAssert, AutomationID: "lblStatus", Name: "Approved"})
	if !ok {
		t.Fatal("want a proposal")
	}
	if as.Subject != SubjectElementName || as.Expected != "Approved" {
		t.Errorf("want the name asserted, got %+v", as)
	}
}

// TestMarkBeforeAnyActionGetsSomethingToHangFrom: the assertion is still what the
// author meant.
func TestMarkBeforeAnyActionGetsSomethingToHangFrom(t *testing.T) {
	j := Emit("x", []Event{{Kind: EventAssert, Name: "Welcome"}})
	if len(j.Steps) != 1 || j.Steps[0].Verb != VerbObserve {
		t.Fatalf("want a single observe step, got %+v", j.Steps)
	}
	if len(j.Steps[0].Assertions) != 1 {
		t.Errorf("the assertion should be attached to it: %+v", j.Steps[0])
	}
	if err := j.Validate(); err != nil {
		t.Errorf("it should validate: %v", err)
	}
}

// TestMarkDoesNotInterruptATypedRun: a mark mid-typing must flush the run rather
// than silently splitting or dropping characters.
func TestMarkDoesNotInterruptATypedRun(t *testing.T) {
	events := append(chars("hello", false), Event{Kind: EventAssert, Name: "Greeting"})
	events = append(events, chars("world", false)...)
	j := Emit("x", events)

	if len(j.Steps) != 2 {
		t.Fatalf("want two type_text steps around the mark, got %+v", j.Steps)
	}
	if j.Steps[0].Text != "hello" || j.Steps[1].Text != "world" {
		t.Errorf("typed runs should survive the mark intact: %+v", j.Steps)
	}
	if len(j.Steps[0].Assertions) != 1 {
		t.Errorf("the mark should attach to the run it followed: %+v", j.Steps[0])
	}
}

// TestEmitPrefersTheAutomationID pins the selector ladder. The automation id is
// the only identifier that survives translation, and the capture path already
// reads it — a recording keyed on the accessible name when an id was available is
// a suite that breaks on a localised build.
func TestEmitPrefersTheAutomationID(t *testing.T) {
	j := Emit("x", []Event{{
		Kind: EventClick, AutomationID: "btnSubmit", Name: "Submit", ControlType: "Button",
	}})
	sel := j.Steps[0].Target
	if sel.AutomationID != "btnSubmit" {
		t.Errorf("want the automation id, got %+v", sel)
	}
	if sel.Name != "" {
		t.Errorf("the name should not also be set, or the selector has two identifiers: %+v", sel)
	}
	if err := j.Validate(); err != nil {
		t.Errorf("the emitted selector should validate: %v", err)
	}
}

func TestEmitClickFallsBackToCoordinates(t *testing.T) {
	j := Emit("x", []Event{{Kind: EventClick, X: 10, Y: 20}})
	if len(j.Steps) != 1 {
		t.Fatalf("want one step, got %d", len(j.Steps))
	}
	sel := j.Steps[0].Target
	if len(sel.Point) != 2 || sel.Point[0] != 10 || sel.Point[1] != 20 {
		t.Errorf("an unnamed click should fall back to coordinates, got %+v", sel)
	}
	if sel.Name != "" || sel.AutomationID != "" {
		t.Error("an unnamed click must not invent an identifier")
	}
}

func TestEmitFoldsTrailingEnterIntoTheTextStep(t *testing.T) {
	events := append(chars("query", false), Event{Kind: EventKey, Key: "Enter"})
	j := Emit("search", events)
	if len(j.Steps) != 1 {
		t.Fatalf("Enter should fold into the type_text step, got %d steps", len(j.Steps))
	}
	if j.Steps[0].Verb != VerbTypeText || !j.Steps[0].Submit {
		t.Errorf("want a type_text with submit, got %+v", j.Steps[0])
	}
}

func TestEmitNonTextKeyBecomesPressKeys(t *testing.T) {
	j := Emit("x", []Event{{Kind: EventKey, Key: "Tab"}})
	if len(j.Steps) != 1 || j.Steps[0].Verb != VerbPressKeys || j.Steps[0].Keys != "Tab" {
		t.Fatalf("a bare Tab should be press_keys, got %+v", j.Steps)
	}
}

// TestEmitTypedTextTargetsTheFocusedField: the click that focused a field is what
// the typing went into, so the step records it rather than relying on whatever
// holds focus at run time.
func TestEmitTypedTextTargetsTheFocusedField(t *testing.T) {
	events := []Event{{Kind: EventClick, AutomationID: "txtSearch", ControlType: "Edit"}}
	events = append(events, chars("hello", false)...)
	j := Emit("x", events)

	if len(j.Steps) != 2 {
		t.Fatalf("want a click then a type_text, got %+v", j.Steps)
	}
	if j.Steps[1].Target == nil || j.Steps[1].Target.AutomationID != "txtSearch" {
		t.Errorf("the type_text should target the field just clicked, got %+v", j.Steps[1].Target)
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
	// Where the password went there must be a credential step, targeting the field
	// it was typed into, naming no secret.
	var found bool
	for _, s := range j.Steps {
		if s.Verb != VerbEnterCredential {
			continue
		}
		found = true
		if s.Credential != "" {
			t.Errorf("the redacted step must name no credential, got %q", s.Credential)
		}
		if s.Target == nil || s.Target.Name != "Password" {
			t.Errorf("the credential step should target the password field, got %+v", s.Target)
		}
	}
	if !found {
		t.Error("an enter_credential step should mark where the password was typed")
	}
}

// TestRedactedDraftDoesNotValidateUntilCompleted: the recorded placeholder names
// no credential, so `journey validate` refuses the draft and says what to supply —
// rather than the journey running and typing nothing into a sign-in form.
func TestRedactedDraftDoesNotValidateUntilCompleted(t *testing.T) {
	j := Emit("sign-in", chars("secret", true))
	err := j.Validate()
	if err == nil {
		t.Fatal("a draft with an unfilled credential should not validate")
	}
	if !strings.Contains(err.Error(), "credential") {
		t.Errorf("the message should say what to fill in, got: %v", err)
	}

	j.Steps[0].Credential = "lab-sso"
	if err := j.Validate(); err != nil {
		t.Errorf("naming the credential should complete the draft: %v", err)
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
	if j.Steps[0].Text != "ab" || j.Steps[2].Text != "cd" {
		t.Errorf("visible runs should be preserved on both sides, got %+v", j.Steps)
	}
	if j.Steps[1].Verb != VerbEnterCredential || j.Steps[1].Text != "" {
		t.Errorf("the middle run should be a credential placeholder, got %+v", j.Steps[1])
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

// TestEmittedJourneyRoundTripsThroughJSON: the recorder writes a file, so the
// document it produces must parse back — including the selector union, which has
// custom marshalling.
func TestEmittedJourneyRoundTripsThroughJSON(t *testing.T) {
	j := Emit("x", []Event{
		{Kind: EventClick, AutomationID: "btnGo", ControlType: "Button"},
		{Kind: EventClick, X: 4, Y: 5},
	})
	blob, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(blob)
	if err != nil {
		t.Fatalf("a recorded journey should parse back: %v\n%s", err, blob)
	}
	if err := back.Validate(); err != nil {
		t.Errorf("and validate: %v", err)
	}
	if len(back.Steps) != len(j.Steps) {
		t.Errorf("round trip changed the step count: %d -> %d", len(j.Steps), len(back.Steps))
	}
}
