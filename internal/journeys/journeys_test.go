package journeys

import (
	"errors"
	"strings"
	"testing"

	"github.com/deploymenttheory/agentweave-harness/guardrails/plan"
)

const goodJourney = `{
  "version": 2,
  "name": "notepad-smoke",
  "description": "type into notepad and verify it shows",
  "steps": [
    {
      "name": "open notepad",
      "verb": "open_app",
      "app": "notepad",
      "assertions": [
        { "subject": "window.title", "operator": "contains", "expected": "Notepad",
          "wait": { "timeout": 15 } }
      ],
      "evidence": [ "notepad open" ]
    },
    {
      "name": "type text",
      "verb": "type_text",
      "text": "hello journeys",
      "assertions": [
        { "subject": "screen.text", "operator": "contains", "expected": "hello journeys" },
        { "subject": "element", "target": { "name": "File" }, "operator": "exists" }
      ]
    }
  ],
  "expected_evidence": [ "notepad open" ]
}`

func TestParseAndValidateGoodJourney(t *testing.T) {
	j, err := Parse([]byte(goodJourney))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := j.Validate(); err != nil {
		t.Fatalf("a well-formed journey should validate: %v", err)
	}
	if j.Name != "notepad-smoke" || len(j.Steps) != 2 {
		t.Fatalf("unexpected parse: %+v", j)
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	if _, err := Parse([]byte(`{"version":2,"name":"x","steps":[],"oops":true}`)); err == nil {
		t.Error("an unknown field should be rejected so a typo does not vanish")
	}
}

func TestWrongVersionIsTyped(t *testing.T) {
	j, _ := Parse([]byte(`{"version":1,"name":"x","steps":[{"verb":"open_app","app":"a"}]}`))
	if err := j.Validate(); !errors.Is(err, ErrJourneyVersion) {
		t.Errorf("want ErrJourneyVersion, got %v", err)
	}
}

// TestValidateRejects is the offline-checking contract of taxonomy §8: everything
// listed there fails at validate, on any platform, with no desktop and no access
// to a tool schema.
func TestValidateRejects(t *testing.T) {
	step := func(body string) string {
		return `{"version":2,"name":"x","steps":[` + body + `]}`
	}
	cases := map[string]string{
		"no name":  `{"version":2,"steps":[{"verb":"click","target":{"name":"a"}}]}`,
		"no steps": `{"version":2,"name":"x","steps":[]}`,
		"no verb":  step(`{"name":"s"}`),
		"unknown verb": step(`{"verb":"frobnicate"}`),

		// Per-verb parameter typing: the check a v1 document could never get.
		"missing required param": step(`{"verb":"set_value","target":{"name":"a"}}`),
		"foreign param":          step(`{"verb":"press_keys","keys":"ctrl+s","value":"nope"}`),
		"target on a verb that takes none": step(`{"verb":"press_keys","keys":"ctrl+s",` +
			`"target":{"name":"a"}}`),

		// Selectors.
		"selector with no identifier":  step(`{"verb":"click","target":{"control_type":"Button"}}`),
		"selector with two":            step(`{"verb":"click","target":{"name":"a","automation_id":"b"}}`),
		"name_match without a name":    step(`{"verb":"click","target":{"automation_id":"b","name_match":"contains"}}`),
		"unknown name_match":           step(`{"verb":"click","target":{"name":"a","name_match":"fuzzy"}}`),
		"unknown scope":                step(`{"verb":"click","target":{"name":"a","scope":"everywhere"}}`),
		"bad selector name pattern":    step(`{"verb":"click","target":{"name":"a(","name_match":"matches"}}`),
		"point of the wrong shape":     step(`{"verb":"click","target":{"point":[1,2,3]}}`),
		"negative occurrence":          step(`{"verb":"click","target":{"name":"a","occurrence":-1}}`),
		"nonsense occurrence":          step(`{"verb":"click","target":{"name":"a","occurrence":"third"}}`),

		// Verb value bounds.
		"bad scroll direction": step(`{"verb":"scroll","direction":"sideways"}`),
		"pause over the cap":   step(`{"verb":"pause","seconds":600}`),
		"url with no scheme":   step(`{"verb":"navigate","url":"example.com"}`),
		"blank credential":     step(`{"verb":"enter_credential","credential":""}`),

		// The subject × operator matrix.
		"unknown subject": step(`{"verb":"observe","assertions":[` +
			`{"subject":"vibes","operator":"is","expected":"x"}]}`),
		"unknown operator": step(`{"verb":"observe","assertions":[` +
			`{"subject":"screen.text","operator":"vibes_with","expected":"x"}]}`),
		"operator not legal for the type": step(`{"verb":"observe","assertions":[` +
			`{"subject":"element.enabled","target":{"name":"a"},"operator":"contains","expected":"x"}]}`),
		"numeric operator on text": step(`{"verb":"observe","assertions":[` +
			`{"subject":"screen.text","operator":"greater_than","expected":3}]}`),

		// Operands.
		"expected of the wrong type": step(`{"verb":"observe","assertions":[` +
			`{"subject":"screen.text","operator":"is","expected":7}]}`),
		"expected on an operator taking none": step(`{"verb":"observe","assertions":[` +
			`{"subject":"element","target":{"name":"a"},"operator":"exists","expected":"x"}]}`),
		"missing expected": step(`{"verb":"observe","assertions":[` +
			`{"subject":"screen.text","operator":"contains"}]}`),
		"empty is_one_of": step(`{"verb":"observe","assertions":[` +
			`{"subject":"screen.text","operator":"is_one_of","expected":[]}]}`),
		"is_one_of with a mistyped member": step(`{"verb":"observe","assertions":[` +
			`{"subject":"screen.text","operator":"is_one_of","expected":["a",2]}]}`),

		// Targets on assertions.
		"assertion subject needing a target": step(`{"verb":"observe","assertions":[` +
			`{"subject":"element.value","operator":"is","expected":"x"}]}`),
		"assertion subject taking no target": step(`{"verb":"observe","assertions":[` +
			`{"subject":"screen.text","target":{"name":"a"},"operator":"contains","expected":"x"}]}`),

		// Regex and waits.
		"pattern does not compile": step(`{"verb":"observe","assertions":[` +
			`{"subject":"screen.text","operator":"matches","expected":"a("}]}`),
		"timeout over the cap": step(`{"verb":"observe","assertions":[` +
			`{"subject":"screen.text","operator":"contains","expected":"x","wait":{"timeout":9000}}]}`),
		"interval longer than the timeout": step(`{"verb":"observe","assertions":[` +
			`{"subject":"screen.text","operator":"contains","expected":"x",` +
			`"wait":{"timeout":1,"interval":5}}]}`),

		// Cross-step rules.
		"result.text with no preceding read": step(`{"verb":"observe","assertions":[` +
			`{"subject":"result.text","operator":"contains","expected":"x"}]}`),
		"dangling expected evidence": `{"version":2,"name":"x",` +
			`"steps":[{"verb":"observe"}],"expected_evidence":["nope"]}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			j, err := Parse([]byte(doc))
			if err != nil {
				return // a parse failure is also a rejection
			}
			if err := j.Validate(); err == nil {
				t.Errorf("%s should fail validation", name)
			}
		})
	}
}

// TestValidateReportsEveryProblemAtOnce: an author fixing a file should not
// discover its problems one run at a time.
func TestValidateReportsEveryProblemAtOnce(t *testing.T) {
	j, err := Parse([]byte(`{"version":2,"name":"","steps":[
		{"verb":"nope"},
		{"verb":"click","target":{}},
		{"verb":"press_keys","keys":"ctrl+s","value":"x"}
	]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = j.Validate()
	if err == nil {
		t.Fatal("want problems")
	}
	if n := strings.Count(err.Error(), "\n  - "); n < 4 {
		t.Errorf("want every problem reported at once, got %d:\n%v", n, err)
	}
}

// TestResultTextIsAllowedAfterARead pins the other half of the cross-step rule:
// the register exists once a read has filled it.
func TestResultTextIsAllowedAfterARead(t *testing.T) {
	j, err := Parse([]byte(`{"version":2,"name":"x","steps":[
		{"verb":"read","target":{"automation_id":"ref"},
		 "assertions":[{"subject":"result.text","operator":"matches","expected":"EXP-[0-9]{6}"}]}
	]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := j.Validate(); err != nil {
		t.Errorf("a result.text assertion on a read step should validate: %v", err)
	}
}

// TestOccurrenceRoundTrips: the union decodes and re-encodes to the form it was
// written in, so a document is not silently rewritten by tooling.
func TestOccurrenceRoundTrips(t *testing.T) {
	cases := map[string]Occurrence{
		`"unique"`: {Mode: OccurrenceUnique},
		`"first"`:  {Mode: OccurrenceFirst},
		`3`:        {Mode: OccurrenceIndex, Index: 3},
	}
	for raw, want := range cases {
		var got Occurrence
		if err := got.UnmarshalJSON([]byte(raw)); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if got != want {
			t.Errorf("%s decoded to %+v, want %+v", raw, got, want)
		}
		back, err := got.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		if string(back) != raw {
			t.Errorf("%s round-tripped to %s", raw, back)
		}
	}
}

// --- compilation ---------------------------------------------------------

// TestCompileInsertsPerceptionBeforeSelectorSteps is the determinism rule of
// taxonomy §4.2: a step that names an element resolves against a snapshot taken as
// part of that step, not against whatever the engine last happened to see.
func TestCompileInsertsPerceptionBeforeSelectorSteps(t *testing.T) {
	j := Journey{Version: SchemaVersion, Name: "x", Steps: []Step{
		{Verb: VerbOpenApp, App: "notepad"},
		{Verb: VerbClick, Target: &Selector{Name: "File"}},
	}}
	doc, err := Compile(j, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	got := toolNames(doc)
	want := []string{"App", "Snapshot", "Click"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("compiled to %v, want %v", got, want)
	}
}

// TestCompileDoesNotRepeatPerception: an explicit observe supplies its own, and a
// second selector step straight after one does not pay for a redundant tree walk.
func TestCompileDoesNotRepeatPerception(t *testing.T) {
	j := Journey{Version: SchemaVersion, Name: "x", Steps: []Step{
		{Verb: VerbObserve},
		{Verb: VerbClick, Target: &Selector{Name: "File"}},
	}}
	doc, err := Compile(j, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if got := toolNames(doc); strings.Join(got, ",") != "Snapshot,Click" {
		t.Errorf("compiled to %v, want one Snapshot then the Click", got)
	}
}

// TestCompileOrdersActionAssertionsEvidence pins the compiled shape.
func TestCompileOrdersActionAssertionsEvidence(t *testing.T) {
	j, _ := Parse([]byte(goodJourney))
	doc, err := Compile(j, "sess-1")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if doc.SessionID != "sess-1" {
		t.Errorf("session id = %q, want it carried through", doc.SessionID)
	}
	if doc.PlanID == "" {
		t.Error("a compiled journey should carry a content id")
	}
	// No Snapshot appears: an assertion perceives for itself, reading the screen at
	// the moment it is evaluated (and on every poll), so the compiler inserts
	// perception only before a *verb* that resolves a selector.
	want := []string{
		"App", "Assert", "CaptureEvidence", // open_app + its assertion + evidence
		"Type", "Assert", "Assert", // type_text + its two assertions
	}
	got := toolNames(doc)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("compiled to %v, want %v", got, want)
	}
}

// TestCompileLowersSelectorsToArguments checks the selector reaches the tool in a
// form it can resolve, including the keys that make resolution strict.
func TestCompileLowersSelectorsToArguments(t *testing.T) {
	j := Journey{Version: SchemaVersion, Name: "x", Steps: []Step{{
		Verb: VerbSetValue, Value: "126.40",
		Target: &Selector{
			Name: "Amount", ControlType: "Edit",
			NameMatch: MatchContains, Occurrence: Occurrence{Mode: OccurrenceIndex, Index: 2},
			Scope: ScopeAnyWindow,
		},
	}}}
	doc, err := Compile(j, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	args := doc.Steps[1].Args // [0] is the inserted Snapshot
	for k, want := range map[string]any{
		"action": "set_value", "value": "126.40",
		"name": "Amount", "control_type": "Edit",
		"name_match": "contains", "occurrence": "2", "scope": "any_window",
	} {
		if args[k] != want {
			t.Errorf("arg %s = %v, want %v", k, args[k], want)
		}
	}
}

// TestCompileOmitsSelectorDefaults: a step's arguments — and so its digest on the
// audit chain — should reflect what the document said, not what the schema filled
// in.
func TestCompileOmitsSelectorDefaults(t *testing.T) {
	args := selectorArgs(&Selector{
		Name: "OK", NameMatch: MatchExact,
		Occurrence: Occurrence{Mode: OccurrenceUnique}, Scope: ScopeForeground,
	})
	for _, k := range []string{"name_match", "occurrence", "scope"} {
		if _, present := args[k]; present {
			t.Errorf("default %s should not be written into the arguments", k)
		}
	}
}

// TestCompileWaitBecomesAModifier: one Assert call whether or not it polls, which
// is what collapsed the two condition vocabularies the old schema reconciled by
// hand.
func TestCompileWaitBecomesAModifier(t *testing.T) {
	j := Journey{Version: SchemaVersion, Name: "x", Steps: []Step{{
		Verb: VerbObserve,
		Assertions: []Assertion{
			{Subject: SubjectScreenText, Operator: OpContains, Expected: "a"},
			{Subject: SubjectScreenText, Operator: OpContains, Expected: "b", Wait: &Wait{Timeout: 15}},
		},
	}}}
	doc, err := Compile(j, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	immediate, polled := doc.Steps[1], doc.Steps[2]
	if immediate.Tool != toolAssert || polled.Tool != toolAssert {
		t.Fatalf("both assertions should be one tool: %s / %s", immediate.Tool, polled.Tool)
	}
	if _, waited := immediate.Args["timeout"]; waited {
		t.Error("an unwaited assertion should carry no timeout")
	}
	if polled.Args["timeout"] != 15.0 {
		t.Errorf("timeout = %v, want 15", polled.Args["timeout"])
	}
	if polled.Args["interval"] != DefaultWaitInterval {
		t.Errorf("interval = %v, want the default applied", polled.Args["interval"])
	}
}

// TestCompileCarriesTheMessageOnPolledAssertions is a regression: the previous
// schema dropped the author's message for every polled assertion, because the
// polling tool had nowhere to put it — so exactly the assertions most likely to
// fail were the ones that failed without an explanation.
func TestCompileCarriesTheMessageOnPolledAssertions(t *testing.T) {
	j := Journey{Version: SchemaVersion, Name: "x", Steps: []Step{{
		Verb: VerbObserve,
		Assertions: []Assertion{{
			Subject: SubjectScreenText, Operator: OpContains, Expected: "ready",
			Message: "the panel finished loading", Wait: &Wait{Timeout: 5},
		}},
	}}}
	doc, err := Compile(j, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if doc.Steps[1].Args["message"] != "the panel finished loading" {
		t.Errorf("a polled assertion must carry its message, got %v", doc.Steps[1].Args)
	}
}

// TestCompileCloseWindowFocusesFirst: sending alt+F4 to whatever happens to be
// foreground is how a journey closes the wrong thing.
func TestCompileCloseWindowFocusesFirst(t *testing.T) {
	j := Journey{Version: SchemaVersion, Name: "x", Steps: []Step{
		{Verb: VerbCloseWindow, Window: "Untitled - Notepad"},
	}}
	doc, err := Compile(j, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if got := toolNames(doc); strings.Join(got, ",") != "App,Shortcut" {
		t.Fatalf("compiled to %v, want a focus then the chord", got)
	}
	if doc.Steps[0].Args["mode"] != "switch" {
		t.Errorf("the first step should focus the window, got %v", doc.Steps[0].Args)
	}
}

// TestCompileIsDeterministic: the same journey compiles to the same plan id, so a
// journey can be pinned by hash the way a plan is.
func TestCompileIsDeterministic(t *testing.T) {
	j, _ := Parse([]byte(goodJourney))
	a, err1 := Compile(j, "s")
	b, err2 := Compile(j, "s")
	if err1 != nil || err2 != nil {
		t.Fatalf("compile: %v %v", err1, err2)
	}
	if a.PlanID != b.PlanID {
		t.Errorf("compilation should be deterministic: %s != %s", a.PlanID, b.PlanID)
	}
}

func TestCompileRejectsAnInvalidJourney(t *testing.T) {
	if _, err := Compile(Journey{Version: SchemaVersion, Name: "x"}, ""); err == nil {
		t.Error("compiling an invalid journey should fail")
	}
}

// TestOriginsAreParallelToSteps is the invariant the run record depends on: an
// origin at index i describes the plan step at index i. If the two ever desync,
// spans are attributed to the wrong verb and the evidence quietly lies.
func TestOriginsAreParallelToSteps(t *testing.T) {
	j := Journey{Version: SchemaVersion, Name: "x", Steps: []Step{
		// close_window lowers to two plan steps, which is where a naive
		// one-origin-per-journey-step mapping would slip.
		{Verb: VerbCloseWindow, Window: "Notepad"},
		{
			Verb: VerbClick, Target: &Selector{Name: "OK"},
			Assertions: []Assertion{{Subject: SubjectScreenText, Operator: OpContains, Expected: "done"}},
			Evidence:   []string{"clicked"},
		},
	}}

	doc, origins, err := CompileWithOrigins(j, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(origins) != len(doc.Steps) {
		t.Fatalf("%d origins for %d steps", len(origins), len(doc.Steps))
	}

	type want struct {
		tool string
		kind OriginKind
		step int
	}
	wants := []want{
		{"App", OriginAction, 0},      // close_window focuses first
		{"Shortcut", OriginAction, 0}, // ...then sends the chord
		{"Snapshot", OriginObserve, 1},
		{"Click", OriginAction, 1},
		{"Assert", OriginAssertion, 1},
		{"CaptureEvidence", OriginEvidence, 1},
	}
	if len(doc.Steps) != len(wants) {
		t.Fatalf("compiled to %v, want %d steps", toolNames(doc), len(wants))
	}
	for i, w := range wants {
		if doc.Steps[i].Tool != w.tool {
			t.Errorf("step %d tool = %s, want %s", i, doc.Steps[i].Tool, w.tool)
		}
		if origins[i].Kind != w.kind {
			t.Errorf("origin %d kind = %s, want %s", i, origins[i].Kind, w.kind)
		}
		if origins[i].StepIndex != w.step {
			t.Errorf("origin %d journey step = %d, want %d", i, origins[i].StepIndex, w.step)
		}
	}

	// The assertion's origin must carry enough to describe it without re-reading
	// the journey, which is what the span attributes are built from.
	a := origins[4]
	if a.Subject != SubjectScreenText || a.Operator != OpContains || a.Expected != "done" {
		t.Errorf("assertion origin lost its comparison: %+v", a)
	}
	if origins[5].Label != "clicked" {
		t.Errorf("evidence origin lost its label: %+v", origins[5])
	}
}

// --- the vocabulary against the taxonomy ---------------------------------

// TestEveryVerbLowers is the exhaustiveness tripwire: adding a verb to the
// vocabulary without a lowering fails here rather than at run time.
func TestEveryVerbLowers(t *testing.T) {
	for v := range verbs {
		t.Run(string(v), func(t *testing.T) {
			steps, err := lowerStep(minimalStep(v), 0)
			if err != nil {
				t.Fatalf("%s does not lower: %v", v, err)
			}
			if len(steps) == 0 {
				t.Fatalf("%s lowered to nothing", v)
			}
			for _, s := range steps {
				if s.Tool == "" {
					t.Errorf("%s lowered to a step naming no tool", v)
				}
			}
		})
	}
}

// TestEveryVerbDerivesTheReachTheTaxonomySays pins docs/journey-taxonomy.md §7
// against the lowering. It is what makes the change manifest for a journey a
// derived fact rather than a description: if a lowering changes so that a verb no
// longer reaches what the table says it reaches, this fails.
func TestEveryVerbDerivesTheReachTheTaxonomySays(t *testing.T) {
	for v, spec := range verbs {
		if spec.kind == "" {
			continue // pause touches nothing derivable
		}
		t.Run(string(v), func(t *testing.T) {
			steps, err := lowerStep(minimalStep(v), 0)
			if err != nil {
				t.Fatalf("lower: %v", err)
			}
			var found bool
			for _, s := range steps {
				for _, tgt := range s.EffectiveTargets() {
					if tgt.Kind == spec.kind && tgt.Verb == spec.reach {
						found = true
					}
				}
			}
			if !found {
				t.Errorf("%s should derive %s/%s; the compiled steps derive %v",
					v, spec.kind, spec.reach, allTargets(steps))
			}
		})
	}
}

// TestUIStepsDeriveANonEmptyManifest is the regression for the defect this
// schema exists to close: every UI tool used to derive nothing, so a journey's
// change manifest was empty and every step rendered as non-destructive.
func TestUIStepsDeriveANonEmptyManifest(t *testing.T) {
	j, _ := Parse([]byte(goodJourney))
	doc, err := Compile(j, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for i, s := range doc.Steps {
		if len(s.EffectiveTargets()) == 0 {
			t.Errorf("step %d (%s) derives no targets, so the manifest understates it", i, s.Tool)
		}
	}
	if !strings.Contains(doc.Render(), "ui") {
		t.Errorf("the manifest should name what the journey touches:\n%s", doc.Render())
	}
}

// TestOperatorMatrixIsSymmetric: every operator applies to at least one value
// type, and every value type has at least one operator, so no row or column of
// taxonomy §5.3 is unreachable.
func TestOperatorMatrixIsSymmetric(t *testing.T) {
	covered := map[ValueType]bool{}
	for op, spec := range operators {
		if len(spec.types) == 0 {
			t.Errorf("operator %s applies to no value type, so nothing can use it", op)
		}
		for _, ty := range spec.types {
			covered[ty] = true
		}
	}
	for _, ty := range []ValueType{TypeText, TypeNumber, TypeBoolean, TypeExistence} {
		if !covered[ty] {
			t.Errorf("value type %s has no operator, so no subject reading one can be asserted on", ty)
		}
	}
	for s, spec := range subjects {
		if !covered[spec.valueType] {
			t.Errorf("subject %s reads %s, which no operator accepts", s, spec.valueType)
		}
	}
}

// --- helpers -------------------------------------------------------------

// minimalStep builds the smallest valid step for a verb, filling exactly its
// required parameters from the vocabulary's own mask — so a new verb is covered by
// the exhaustiveness tests without anyone remembering to extend this.
func minimalStep(v Verb) Step {
	s := Step{Verb: v}
	req := verbs[v].required
	if req&pTarget != 0 {
		s.Target = &Selector{Name: "Element"}
	}
	if req&pApp != 0 {
		s.App = "notepad"
	}
	if req&pWindow != 0 {
		s.Window = "Untitled - Notepad"
	}
	if req&pURL != 0 {
		s.URL = "https://example.com/path"
	}
	if req&pValue != 0 {
		s.Value = "v"
	}
	if req&pText != 0 {
		s.Text = "t"
	}
	if req&pKeys != 0 {
		s.Keys = "ctrl+s"
	}
	if req&pCredential != 0 {
		s.Credential = "lab-sso"
	}
	if req&pLabel != 0 {
		s.Label = "evidence"
	}
	if req&pDirection != 0 {
		s.Direction = "down"
	}
	if req&pSeconds != 0 {
		s.Seconds = 1
	}
	return s
}

func toolNames(doc plan.Document) []string {
	out := make([]string, len(doc.Steps))
	for i, s := range doc.Steps {
		out[i] = s.Tool
	}
	return out
}

func allTargets(steps []plan.Step) []plan.Target {
	var out []plan.Target
	for _, s := range steps {
		out = append(out, s.EffectiveTargets()...)
	}
	return out
}
