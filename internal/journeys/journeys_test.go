package journeys

import (
	"errors"
	"strings"
	"testing"
)

const goodJourney = `{
  "version": 1,
  "name": "notepad-smoke",
  "description": "type into notepad and verify it shows",
  "steps": [
    {
      "name": "open notepad",
      "tool": "App",
      "args": { "name": "notepad" },
      "assertions": [ { "kind": "wait_window_active", "target": "Notepad", "timeout": 15 } ],
      "evidence": [ "notepad open" ]
    },
    {
      "name": "type text",
      "tool": "Type",
      "args": { "text": "hello journeys" },
      "assertions": [
        { "kind": "text_present", "target": "hello journeys" },
        { "kind": "element_present", "target": "File" }
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
	if _, err := Parse([]byte(`{"version":1,"name":"x","steps":[],"oops":true}`)); err == nil {
		t.Error("an unknown field should be rejected so a typo does not vanish")
	}
}

func TestValidateCollectsProblems(t *testing.T) {
	cases := map[string]string{
		"wrong version":       `{"version":2,"name":"x","steps":[{"tool":"App"}]}`,
		"no name":             `{"version":1,"steps":[{"tool":"App"}]}`,
		"no steps":            `{"version":1,"name":"x","steps":[]}`,
		"step without a tool": `{"version":1,"name":"x","steps":[{"name":"s"}]}`,
		"unknown assertion":   `{"version":1,"name":"x","steps":[{"tool":"App","assertions":[{"kind":"nope","target":"t"}]}]}`,
		"assertion no target": `{"version":1,"name":"x","steps":[{"tool":"App","assertions":[{"kind":"text_present","target":""}]}]}`,
		"timeout on immediate": `{"version":1,"name":"x","steps":[{"tool":"App","assertions":` +
			`[{"kind":"text_present","target":"t","timeout":5}]}]}`,
		"dangling expected evidence": `{"version":1,"name":"x","steps":[{"tool":"App"}],"expected_evidence":["nope"]}`,
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

func TestWrongVersionIsTyped(t *testing.T) {
	j, _ := Parse([]byte(`{"version":99,"name":"x","steps":[{"tool":"App"}]}`))
	if err := j.Validate(); !errors.Is(err, ErrJourneyVersion) {
		t.Errorf("want ErrJourneyVersion, got %v", err)
	}
}

// TestCompileProducesActionAssertEvidenceOrder pins the compiled shape: an action
// step, then its assertions, then its evidence, in order across the journey.
func TestCompileProducesActionAssertEvidenceOrder(t *testing.T) {
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

	gotTools := make([]string, len(doc.Steps))
	for i, s := range doc.Steps {
		gotTools[i] = s.Tool
	}
	want := []string{"App", "WaitFor", "CaptureEvidence", "Type", "Assert", "Assert"}
	if strings.Join(gotTools, ",") != strings.Join(want, ",") {
		t.Errorf("compiled tool order = %v, want %v", gotTools, want)
	}
}

// TestCompileMapsAssertionsToToolArgs checks each assertion kind lands on the
// right tool and condition, so the executor actually checks what was asked.
func TestCompileMapsAssertionsToToolArgs(t *testing.T) {
	j := Journey{
		Version: 1, Name: "m", Steps: []Step{{
			Tool: "App", Args: map[string]any{"name": "x"},
			Assertions: []Assertion{
				{Kind: AssertElementPresent, Target: "OK"},
				{Kind: AssertTextPresent, Target: "hi"},
				{Kind: AssertTextAbsent, Target: "err"},
				{Kind: AssertWindowActive, Target: "Notepad"},
				{Kind: AssertWaitTextPresent, Target: "ready", Timeout: 20},
				{Kind: AssertWaitElementPresent, Target: "Save"},
				{Kind: AssertWaitWindowActive, Target: "Dialog"},
			},
		}},
	}
	doc, err := Compile(j, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// steps[0] is the App action; assertions follow.
	type want struct {
		tool, condKey, cond, valKey, val string
		timeout                          int
	}
	wants := []want{
		{"Assert", "condition", "element_present", "text", "OK", 0},
		{"Assert", "condition", "text_present", "text", "hi", 0},
		{"Assert", "condition", "text_absent", "text", "err", 0},
		{"Assert", "condition", "window_active", "window_name", "Notepad", 0},
		{"WaitFor", "condition", "text_exists", "text", "ready", 20},
		{"WaitFor", "condition", "element_exists", "text", "Save", 0},
		{"WaitFor", "condition", "active_window", "window_name", "Dialog", 0},
	}
	for i, w := range wants {
		s := doc.Steps[i+1]
		if s.Tool != w.tool {
			t.Errorf("assertion %d tool = %s, want %s", i, s.Tool, w.tool)
		}
		if s.Args[w.condKey] != w.cond {
			t.Errorf("assertion %d %s = %v, want %s", i, w.condKey, s.Args[w.condKey], w.cond)
		}
		if s.Args[w.valKey] != w.val {
			t.Errorf("assertion %d %s = %v, want %s", i, w.valKey, s.Args[w.valKey], w.val)
		}
		if w.timeout > 0 && s.Args["timeout"] != w.timeout {
			t.Errorf("assertion %d timeout = %v, want %d", i, s.Args["timeout"], w.timeout)
		}
		if w.timeout == 0 {
			if _, ok := s.Args["timeout"]; ok {
				t.Errorf("assertion %d should carry no timeout", i)
			}
		}
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
	if _, err := Compile(Journey{Version: 1}, ""); err == nil {
		t.Error("compiling an invalid journey should fail")
	}
}
