package windows

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// This file is the assertion algebra: subject × operator × expected, as specified
// in docs/journey-taxonomy.md §5. It is deliberately free of any Windows or MCP
// type — it compares an Observation against an expected value — so the whole
// comparison surface is unit-testable on any platform, which is where the
// interesting cases live.
//
// Reading the observation from the desktop is the Assert tool's job (testing.go);
// deciding whether it satisfies the assertion is this file's.

// Assertion subjects. The set is closed and matches the journey vocabulary.
const (
	SubjectScreenText         = "screen.text"
	SubjectWindowTitle        = "window.title"
	SubjectWindow             = "window"
	SubjectElement            = "element"
	SubjectElementName        = "element.name"
	SubjectElementValue       = "element.value"
	SubjectElementControlType = "element.control_type"
	SubjectElementEnabled     = "element.enabled"
	SubjectElementChecked     = "element.checked"
	SubjectElementSelected    = "element.selected"
	SubjectElementFocused     = "element.focused"
	SubjectElementCount       = "element.count"
	SubjectResultText         = "result.text"
)

// AssertSubjects is every subject the Assert tool evaluates, for its schema enum.
var AssertSubjects = []any{
	SubjectScreenText, SubjectWindowTitle, SubjectWindow, SubjectElement,
	SubjectElementName, SubjectElementValue, SubjectElementControlType,
	SubjectElementEnabled, SubjectElementChecked, SubjectElementSelected,
	SubjectElementFocused, SubjectElementCount, SubjectResultText,
}

// Assertion operators.
const (
	OpIs             = "is"
	OpIsNot          = "is_not"
	OpContains       = "contains"
	OpDoesNotContain = "does_not_contain"
	OpStartsWith     = "starts_with"
	OpEndsWith       = "ends_with"
	OpMatches        = "matches"
	OpDoesNotMatch   = "does_not_match"
	OpIsEmpty        = "is_empty"
	OpIsNotEmpty     = "is_not_empty"
	OpIsOneOf        = "is_one_of"
	OpIsNotOneOf     = "is_not_one_of"
	OpIsTrue         = "is_true"
	OpIsFalse        = "is_false"
	OpExists         = "exists"
	OpDoesNotExist   = "does_not_exist"
	OpGreaterThan    = "greater_than"
	OpGreaterOrEqual = "greater_or_equal"
	OpLessThan       = "less_than"
	OpLessOrEqual    = "less_or_equal"
)

// AssertOperators is every operator the Assert tool evaluates, for its schema enum.
var AssertOperators = []any{
	OpIs, OpIsNot, OpContains, OpDoesNotContain, OpStartsWith, OpEndsWith,
	OpMatches, OpDoesNotMatch, OpIsEmpty, OpIsNotEmpty, OpIsOneOf, OpIsNotOneOf,
	OpIsTrue, OpIsFalse, OpExists, OpDoesNotExist,
	OpGreaterThan, OpGreaterOrEqual, OpLessThan, OpLessOrEqual,
}

// ValueKind is the type of value a subject reads.
type ValueKind string

const (
	KindText      ValueKind = "text"
	KindNumber    ValueKind = "number"
	KindBoolean   ValueKind = "boolean"
	KindExistence ValueKind = "existence"
)

// SubjectKind returns the value type a subject reads, and whether the subject is
// one this build evaluates.
func SubjectKind(subject string) (ValueKind, bool) {
	switch subject {
	case SubjectScreenText, SubjectWindowTitle, SubjectElementName,
		SubjectElementValue, SubjectElementControlType, SubjectResultText:
		return KindText, true
	case SubjectElementCount:
		return KindNumber, true
	case SubjectElementEnabled, SubjectElementChecked, SubjectElementSelected, SubjectElementFocused:
		return KindBoolean, true
	case SubjectWindow, SubjectElement:
		return KindExistence, true
	default:
		return "", false
	}
}

// SubjectNeedsTarget reports whether a subject reads a particular element or
// window and therefore needs a selector.
func SubjectNeedsTarget(subject string) bool {
	switch subject {
	case SubjectWindow, SubjectElement, SubjectElementName, SubjectElementValue,
		SubjectElementControlType, SubjectElementEnabled, SubjectElementChecked,
		SubjectElementSelected, SubjectElementFocused, SubjectElementCount:
		return true
	default:
		return false
	}
}

// Observation is what was actually read from the desktop. Absent marks a subject
// that could not be read at all — a toggle state on a control that has none — so
// a failure can say that rather than reporting a misleading false.
type Observation struct {
	Kind   ValueKind
	Text   string
	Number float64
	Bool   bool
	Exists bool

	Absent bool
	// AbsentReason explains what was missing, and is what the failure reports.
	AbsentReason string
}

// Render renders the observed value for a failure message and for the run
// record's journey.assertion.observed attribute. It is the thing a text log never
// carried: a failure that reports only the condition name says a test broke, one
// that reports what was on screen usually says why.
func (o Observation) Render() string {
	if o.Absent {
		return "<" + o.AbsentReason + ">"
	}
	switch o.Kind {
	case KindText:
		return strconv.Quote(o.Text)
	case KindNumber:
		return strconv.FormatFloat(o.Number, 'f', -1, 64)
	case KindBoolean:
		return strconv.FormatBool(o.Bool)
	case KindExistence:
		if o.Exists {
			return "present"
		}
		return "absent"
	default:
		return "?"
	}
}

// CompareOptions are the text-comparison modifiers, all defaulting off so
// behaviour is never implicit. The behaviour they replace folded case for window
// titles and for nothing else, and said so nowhere.
type CompareOptions struct {
	IgnoreCase         bool
	Trim               bool
	CollapseWhitespace bool
}

// ErrAssertionShape reports an assertion that cannot be evaluated as written —
// an operator that does not apply to the subject, or a missing or mistyped
// expected value. It is distinct from a failed assertion: the first is a broken
// document, the second is a broken application.
var ErrAssertionShape = fmt.Errorf("the assertion cannot be evaluated as written")

var collapseRE = regexp.MustCompile(`\s+`)

// EvalAssertion decides whether an observation satisfies operator/expected.
//
// It returns an error only for an assertion that is malformed; a condition that
// simply does not hold returns (false, nil). An absent subject never satisfies
// anything except does_not_exist, and never errors — the control not having a
// toggle state is a fact about the application, which is what the run is testing.
func EvalAssertion(operator string, obs Observation, expected any, opts CompareOptions) (bool, error) {
	spec, ok := operatorApplies(operator, obs.Kind)
	if !ok {
		return false, fmt.Errorf("%w: operator %q does not apply to a %s value",
			ErrAssertionShape, operator, obs.Kind)
	}
	if err := spec.checkOperand(operator, expected, obs.Kind); err != nil {
		return false, err
	}
	if obs.Absent {
		return operator == OpDoesNotExist, nil
	}

	switch obs.Kind {
	case KindExistence:
		return evalExistence(operator, obs), nil
	case KindBoolean:
		return evalBoolean(operator, obs, expected)
	case KindNumber:
		return evalNumber(operator, obs, expected)
	default:
		return evalText(operator, obs, expected, opts)
	}
}

func evalExistence(operator string, obs Observation) bool {
	if operator == OpExists {
		return obs.Exists
	}
	return !obs.Exists
}

func evalBoolean(operator string, obs Observation, expected any) (bool, error) {
	switch operator {
	case OpIsTrue:
		return obs.Bool, nil
	case OpIsFalse:
		return !obs.Bool, nil
	}
	want, ok := coerceBool(expected)
	if !ok {
		return false, fmt.Errorf("%w: expected %v is not a true/false value", ErrAssertionShape, expected)
	}
	if operator == OpIs {
		return obs.Bool == want, nil
	}
	return obs.Bool != want, nil
}

func evalNumber(operator string, obs Observation, expected any) (bool, error) {
	if operator == OpIsOneOf || operator == OpIsNotOneOf {
		list, ok := expected.([]any)
		if !ok {
			return false, fmt.Errorf("%w: operator %q needs an array", ErrAssertionShape, operator)
		}
		var hit bool
		for _, item := range list {
			if n, ok := coerceNumber(item); ok && n == obs.Number {
				hit = true
				break
			}
		}
		return hit == (operator == OpIsOneOf), nil
	}

	want, ok := coerceNumber(expected)
	if !ok {
		return false, fmt.Errorf("%w: expected %v is not a number", ErrAssertionShape, expected)
	}
	switch operator {
	case OpIs:
		return obs.Number == want, nil
	case OpIsNot:
		return obs.Number != want, nil
	case OpGreaterThan:
		return obs.Number > want, nil
	case OpGreaterOrEqual:
		return obs.Number >= want, nil
	case OpLessThan:
		return obs.Number < want, nil
	case OpLessOrEqual:
		return obs.Number <= want, nil
	}
	return false, fmt.Errorf("%w: operator %q", ErrAssertionShape, operator)
}

func evalText(operator string, obs Observation, expected any, opts CompareOptions) (bool, error) {
	got := normalize(obs.Text, opts)

	switch operator {
	case OpIsEmpty:
		return got == "", nil
	case OpIsNotEmpty:
		return got != "", nil
	case OpIsOneOf, OpIsNotOneOf:
		list, ok := expected.([]any)
		if !ok {
			return false, fmt.Errorf("%w: operator %q needs an array", ErrAssertionShape, operator)
		}
		var hit bool
		for _, item := range list {
			if normalizeExpected(item, opts) == got {
				hit = true
				break
			}
		}
		return hit == (operator == OpIsOneOf), nil
	}

	want := normalizeExpected(expected, opts)
	switch operator {
	case OpIs:
		return got == want, nil
	case OpIsNot:
		return got != want, nil
	case OpContains:
		return strings.Contains(got, want), nil
	case OpDoesNotContain:
		return !strings.Contains(got, want), nil
	case OpStartsWith:
		return strings.HasPrefix(got, want), nil
	case OpEndsWith:
		return strings.HasSuffix(got, want), nil
	case OpMatches, OpDoesNotMatch:
		// A full match, not a search. An unanchored pattern that happens to match a
		// fragment is the regex equivalent of the substring fallback that strict
		// selectors exist to remove; write .* to relax it deliberately.
		re, err := compileFull(fmt.Sprint(expected), opts.IgnoreCase)
		if err != nil {
			return false, err
		}
		return re.MatchString(got) == (operator == OpMatches), nil
	}
	return false, fmt.Errorf("%w: operator %q", ErrAssertionShape, operator)
}

// compileFull anchors a pattern at both ends. RE2 does not backtrack, so a
// pathological pattern cannot hang a run.
func compileFull(pattern string, ignoreCase bool) (*regexp.Regexp, error) {
	prefix := `\A(?:`
	if ignoreCase {
		prefix = `\A(?i:`
	}
	re, err := regexp.Compile(prefix + pattern + `)\z`)
	if err != nil {
		return nil, fmt.Errorf("%w: pattern %q does not compile: %w", ErrAssertionShape, pattern, err)
	}
	return re, nil
}

// normalize applies NFC and the comparison modifiers. NFC first, so a modifier
// operates on the same representation on both sides of a comparison.
func normalize(s string, opts CompareOptions) string {
	s = norm.NFC.String(s)
	if opts.CollapseWhitespace {
		s = collapseRE.ReplaceAllString(s, " ")
	}
	if opts.Trim {
		s = strings.TrimSpace(s)
	}
	if opts.IgnoreCase {
		s = strings.ToLower(s)
	}
	return s
}

// normalizeExpected renders and normalizes an expected value. Trim is not applied
// to it: trimming is about what the screen reported, not about what the author
// wrote, and silently trimming a document's own value would hide a typo.
func normalizeExpected(v any, opts CompareOptions) string {
	s := norm.NFC.String(fmt.Sprint(v))
	if opts.CollapseWhitespace {
		s = collapseRE.ReplaceAllString(s, " ")
	}
	if opts.IgnoreCase {
		s = strings.ToLower(s)
	}
	return s
}

// operandKind says what shape of expected an operator takes.
type operandKind int

const (
	operandNone operandKind = iota
	operandScalar
	operandList
)

type opSpec struct {
	kinds   []ValueKind
	operand operandKind
}

// checkOperand rejects a missing operand, and an operand supplied to an operator
// that takes none. Ignoring a field the author wrote is how a document comes to
// mean something other than it says.
func (s opSpec) checkOperand(operator string, expected any, _ ValueKind) error {
	switch s.operand {
	case operandNone:
		if expected != nil {
			return fmt.Errorf("%w: operator %q takes no expected value", ErrAssertionShape, operator)
		}
	case operandScalar:
		if expected == nil {
			return fmt.Errorf("%w: operator %q needs an expected value", ErrAssertionShape, operator)
		}
	case operandList:
		list, ok := expected.([]any)
		if !ok || len(list) == 0 {
			return fmt.Errorf("%w: operator %q needs a non-empty array of expected values",
				ErrAssertionShape, operator)
		}
	}
	return nil
}

// operatorApplies is the matrix of taxonomy §5.3, read by lookup.
func operatorApplies(operator string, kind ValueKind) (opSpec, bool) {
	text, num, boolean, exist := KindText, KindNumber, KindBoolean, KindExistence
	table := map[string]opSpec{
		OpIs:             {[]ValueKind{text, num, boolean}, operandScalar},
		OpIsNot:          {[]ValueKind{text, num, boolean}, operandScalar},
		OpContains:       {[]ValueKind{text}, operandScalar},
		OpDoesNotContain: {[]ValueKind{text}, operandScalar},
		OpStartsWith:     {[]ValueKind{text}, operandScalar},
		OpEndsWith:       {[]ValueKind{text}, operandScalar},
		OpMatches:        {[]ValueKind{text}, operandScalar},
		OpDoesNotMatch:   {[]ValueKind{text}, operandScalar},
		OpIsEmpty:        {[]ValueKind{text}, operandNone},
		OpIsNotEmpty:     {[]ValueKind{text}, operandNone},
		OpIsOneOf:        {[]ValueKind{text, num}, operandList},
		OpIsNotOneOf:     {[]ValueKind{text, num}, operandList},
		OpIsTrue:         {[]ValueKind{boolean}, operandNone},
		OpIsFalse:        {[]ValueKind{boolean}, operandNone},
		OpExists:         {[]ValueKind{exist}, operandNone},
		OpDoesNotExist:   {[]ValueKind{exist}, operandNone},
		OpGreaterThan:    {[]ValueKind{num}, operandScalar},
		OpGreaterOrEqual: {[]ValueKind{num}, operandScalar},
		OpLessThan:       {[]ValueKind{num}, operandScalar},
		OpLessOrEqual:    {[]ValueKind{num}, operandScalar},
	}
	spec, ok := table[operator]
	if !ok {
		return opSpec{}, false
	}
	for _, k := range spec.kinds {
		if k == kind {
			return spec, true
		}
	}
	return opSpec{}, false
}

// coerceNumber accepts the value shapes a JSON decoder and a stringifying client
// both produce.
func coerceNumber(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case string:
		n, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return n, err == nil
	default:
		return 0, false
	}
}

// coerceBool accepts the same shapes params.go does, for the same reason: Claude
// Desktop stringifies booleans.
func coerceBool(v any) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case string:
		switch strings.ToLower(strings.TrimSpace(x)) {
		case "true", "1", "yes":
			return true, true
		case "false", "0", "no":
			return false, true
		}
	}
	return false, false
}
