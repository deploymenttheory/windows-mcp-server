package windows

import (
	"errors"
	"testing"
)

// The assertion algebra is where a journey's verdict is actually decided, and it
// is deliberately free of Windows and MCP types so the whole comparison surface
// can be exercised here rather than on a desktop.

func text(s string) Observation  { return Observation{Kind: KindText, Text: s} }
func number(n float64) Observation { return Observation{Kind: KindNumber, Number: n} }
func boolean(b bool) Observation { return Observation{Kind: KindBoolean, Bool: b} }
func exists(b bool) Observation  { return Observation{Kind: KindExistence, Exists: b} }

func TestEvalText(t *testing.T) {
	obs := text("Total: £126.40")
	cases := []struct {
		op       string
		expected any
		want     bool
	}{
		{OpIs, "Total: £126.40", true},
		{OpIs, "Total: £12.40", false},
		{OpIsNot, "something else", true},
		{OpContains, "126.40", true},
		{OpContains, "999", false},
		{OpDoesNotContain, "999", true},
		{OpStartsWith, "Total", true},
		{OpStartsWith, "otal", false},
		{OpEndsWith, "£126.40", true},
		{OpIsOneOf, []any{"nope", "Total: £126.40"}, true},
		{OpIsNotOneOf, []any{"nope", "also nope"}, true},
	}
	for _, tc := range cases {
		got, err := EvalAssertion(tc.op, obs, tc.expected, CompareOptions{})
		if err != nil {
			t.Errorf("%s %v: %v", tc.op, tc.expected, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s %v = %v, want %v", tc.op, tc.expected, got, tc.want)
		}
	}
}

// TestMatchesIsAFullMatch is the operator's whole point. An unanchored pattern
// that happens to match a fragment is the regex equivalent of the substring
// fallback strict selectors exist to remove — so a reference of the wrong length
// must fail, and relaxing it has to be written out.
func TestMatchesIsAFullMatch(t *testing.T) {
	pattern := "EXP-[0-9]{6}"
	cases := map[string]bool{
		"EXP-447123":         true,
		"EXP-4471":           false, // too short: a search would have passed this
		"EXP-447123-EXTRA":   false, // trailing junk: a search would have passed this too
		"prefix EXP-447123":  false,
	}
	for observed, want := range cases {
		got, err := EvalAssertion(OpMatches, text(observed), pattern, CompareOptions{})
		if err != nil {
			t.Fatalf("%q: %v", observed, err)
		}
		if got != want {
			t.Errorf("matches %q against %q = %v, want %v", pattern, observed, got, want)
		}
	}

	// Relaxing it is available, and explicit.
	got, err := EvalAssertion(OpMatches, text("prefix EXP-447123"), ".*EXP-[0-9]{6}", CompareOptions{})
	if err != nil || !got {
		t.Errorf("an explicitly relaxed pattern should match: %v %v", got, err)
	}
}

func TestMatchesRejectsABadPatternAsAShapeError(t *testing.T) {
	_, err := EvalAssertion(OpMatches, text("x"), "a(", CompareOptions{})
	if !errors.Is(err, ErrAssertionShape) {
		t.Errorf("a pattern that does not compile is a broken document, not a failed test: %v", err)
	}
}

// TestCompareModifiersDefaultOff pins that nothing is implicit. The behaviour
// this replaced folded case for window titles and for nothing else, and said so
// nowhere.
func TestCompareModifiersDefaultOff(t *testing.T) {
	obs := text("  Save   As  ")

	if got, _ := EvalAssertion(OpIs, obs, "save as", CompareOptions{}); got {
		t.Error("case and whitespace should matter unless the document says otherwise")
	}
	if got, _ := EvalAssertion(OpIs, obs, "Save   As", CompareOptions{Trim: true}); !got {
		t.Error("trim should strip the surrounding whitespace")
	}
	if got, _ := EvalAssertion(OpIs, obs, " Save As ", CompareOptions{CollapseWhitespace: true}); !got {
		t.Error("collapse_whitespace should reduce the internal run")
	}
	if got, _ := EvalAssertion(OpIs, obs, "save   as",
		CompareOptions{Trim: true, IgnoreCase: true}); !got {
		t.Error("the modifiers should compose")
	}
}

// TestIgnoreCaseAppliesToRegexToo: a modifier that silently applied to some
// operators and not others would be the inconsistency this design removed.
func TestIgnoreCaseAppliesToRegexToo(t *testing.T) {
	got, err := EvalAssertion(OpMatches, text("SAVED"), "saved", CompareOptions{IgnoreCase: true})
	if err != nil || !got {
		t.Errorf("ignore_case should reach the pattern: %v %v", got, err)
	}
}

func TestEvalNumber(t *testing.T) {
	cases := []struct {
		op       string
		observed float64
		expected any
		want     bool
	}{
		{OpIs, 3, 3.0, true},
		{OpIsNot, 3, 4.0, true},
		{OpGreaterThan, 3, 2.0, true},
		{OpGreaterThan, 3, 3.0, false},
		{OpGreaterOrEqual, 3, 3.0, true},
		{OpLessThan, 3, 4.0, true},
		{OpLessOrEqual, 3, 3.0, true},
		{OpIsOneOf, 3, []any{1.0, 3.0}, true},
		{OpIsNotOneOf, 3, []any{1.0, 2.0}, true},
		// A stringified number, which some MCP clients produce.
		{OpIs, 3, "3", true},
	}
	for _, tc := range cases {
		got, err := EvalAssertion(tc.op, number(tc.observed), tc.expected, CompareOptions{})
		if err != nil {
			t.Errorf("%s %v: %v", tc.op, tc.expected, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%v %s %v = %v, want %v", tc.observed, tc.op, tc.expected, got, tc.want)
		}
	}
}

func TestEvalBoolean(t *testing.T) {
	if got, _ := EvalAssertion(OpIsTrue, boolean(true), nil, CompareOptions{}); !got {
		t.Error("is_true should pass on true")
	}
	if got, _ := EvalAssertion(OpIsFalse, boolean(true), nil, CompareOptions{}); got {
		t.Error("is_false should fail on true")
	}
	// is and is_true are the same check; both spellings exist because one reads
	// better by hand and the other reads better when generated.
	if got, _ := EvalAssertion(OpIs, boolean(true), true, CompareOptions{}); !got {
		t.Error("is true should agree with is_true")
	}
	if got, _ := EvalAssertion(OpIs, boolean(false), "false", CompareOptions{}); !got {
		t.Error("a stringified boolean should be accepted, as elsewhere in the params layer")
	}
}

func TestEvalExistence(t *testing.T) {
	if got, _ := EvalAssertion(OpExists, exists(true), nil, CompareOptions{}); !got {
		t.Error("exists should pass when present")
	}
	if got, _ := EvalAssertion(OpDoesNotExist, exists(false), nil, CompareOptions{}); !got {
		t.Error("does_not_exist should pass when absent")
	}
}

// TestAbsentSubjectFailsEverythingButDoesNotExist: a Button has no checked state,
// and reporting that as "unchecked" would make an is_false assertion pass on a
// control that has no such state at all.
func TestAbsentSubjectFailsEverythingButDoesNotExist(t *testing.T) {
	absent := Observation{Kind: KindBoolean, Absent: true, AbsentReason: "the element has no checked state"}

	for _, op := range []string{OpIsTrue, OpIsFalse} {
		got, err := EvalAssertion(op, absent, nil, CompareOptions{})
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if got {
			t.Errorf("%s should not pass on a subject that could not be read", op)
		}
	}

	missing := Observation{Kind: KindExistence, Absent: true, AbsentReason: "no matching element"}
	if got, _ := EvalAssertion(OpDoesNotExist, missing, nil, CompareOptions{}); !got {
		t.Error("does_not_exist is the one thing an absent subject satisfies")
	}
	if got := absent.Render(); got != "<the element has no checked state>" {
		t.Errorf("an absent observation should render its reason, got %s", got)
	}
}

// TestOperatorMatrixIsEnforced: an operator that does not apply to the subject's
// value type is a broken document, and must be distinguishable from a failed
// test — otherwise an author debugs the application instead of the journey.
func TestOperatorMatrixIsEnforced(t *testing.T) {
	cases := []struct {
		op  string
		obs Observation
	}{
		{OpContains, number(3)},
		{OpGreaterThan, text("x")},
		{OpIsTrue, text("x")},
		{OpExists, text("x")},
		{OpIsEmpty, boolean(true)},
		{OpIs, exists(true)},
	}
	for _, tc := range cases {
		_, err := EvalAssertion(tc.op, tc.obs, "x", CompareOptions{})
		if !errors.Is(err, ErrAssertionShape) {
			t.Errorf("%s on a %s value should be a shape error, got %v", tc.op, tc.obs.Kind, err)
		}
	}
}

// TestOperandsAreChecked: supplying an expected value to an operator that takes
// none must fail rather than be ignored. Silently dropping a field the author
// wrote is how a document comes to mean something other than it says.
func TestOperandsAreChecked(t *testing.T) {
	if _, err := EvalAssertion(OpExists, exists(true), "surprise", CompareOptions{}); !errors.Is(err, ErrAssertionShape) {
		t.Error("an expected value on exists should be rejected, not ignored")
	}
	if _, err := EvalAssertion(OpContains, text("x"), nil, CompareOptions{}); !errors.Is(err, ErrAssertionShape) {
		t.Error("a missing expected value should be rejected")
	}
	if _, err := EvalAssertion(OpIsOneOf, text("x"), "not an array", CompareOptions{}); !errors.Is(err, ErrAssertionShape) {
		t.Error("is_one_of needs an array")
	}
	if _, err := EvalAssertion(OpIsOneOf, text("x"), []any{}, CompareOptions{}); !errors.Is(err, ErrAssertionShape) {
		t.Error("is_one_of needs a non-empty array")
	}
}

// TestSubjectKindsAndTargets pins the subject table the Assert schema advertises.
func TestSubjectKindsAndTargets(t *testing.T) {
	for _, s := range AssertSubjects {
		subject := s.(string)
		if _, ok := SubjectKind(subject); !ok {
			t.Errorf("subject %s is advertised but has no value kind", subject)
		}
	}
	if _, ok := SubjectKind("vibes"); ok {
		t.Error("an unknown subject should not resolve to a kind")
	}

	needs := map[string]bool{
		SubjectElementValue: true, SubjectElementCount: true, SubjectElement: true,
		SubjectScreenText: false, SubjectWindowTitle: false, SubjectResultText: false,
	}
	for subject, want := range needs {
		if got := SubjectNeedsTarget(subject); got != want {
			t.Errorf("SubjectNeedsTarget(%s) = %v, want %v", subject, got, want)
		}
	}
}

// TestObservationRender is what journey.assertion.observed carries: the thing a
// failure message never used to say.
func TestObservationRender(t *testing.T) {
	cases := map[string]Observation{
		`"hello"`: text("hello"),
		"3":       number(3),
		"3.5":     number(3.5),
		"true":    boolean(true),
		"present": exists(true),
		"absent":  exists(false),
	}
	for want, obs := range cases {
		if got := obs.Render(); got != want {
			t.Errorf("Render() = %s, want %s", got, want)
		}
	}
}
