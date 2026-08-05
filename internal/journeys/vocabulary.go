package journeys

import (
	"slices"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/plan"
)

// This file is docs/journey-taxonomy.md expressed as data: the closed sets of
// verbs, subjects and operators, which parameters each verb takes, and which
// operators are legal for which value type. Keeping the vocabulary as tables
// rather than as switch statements is what makes it checkable — an unlisted
// combination is rejected by lookup rather than by a forgotten case, and
// TestEveryVerbLowers, TestEveryVerbDerivesTheReachTheTaxonomySays and
// TestOperatorMatrixIsSymmetric pin the tables against the document.
//
// The tables are also what let this package stay platform-agnostic. The verbs
// carry their own types, so validation needs no access to the Windows-only tool
// schemas, and a journey is fully checkable in CI on any host.

// Verb is one action a journey step performs. The set is closed: it is the whole
// vocabulary a journey may be written in (taxonomy §3).
type Verb string

// The verbs, grouped as the taxonomy groups them.
const (
	// Lifecycle.
	VerbOpenApp      Verb = "open_app"
	VerbFocusWindow  Verb = "focus_window"
	VerbResizeWindow Verb = "resize_window"
	VerbCloseWindow  Verb = "close_window"

	// Navigation.
	VerbNavigate Verb = "navigate"
	VerbScroll   Verb = "scroll"

	// Direct manipulation.
	VerbClick       Verb = "click"
	VerbDoubleClick Verb = "double_click"
	VerbRightClick  Verb = "right_click"
	VerbHover       Verb = "hover"

	// Control operations, via UIA patterns.
	VerbInvoke   Verb = "invoke"
	VerbToggle   Verb = "toggle"
	VerbSelect   Verb = "select"
	VerbExpand   Verb = "expand"
	VerbCollapse Verb = "collapse"

	// Text entry.
	VerbSetValue  Verb = "set_value"
	VerbTypeText  Verb = "type_text"
	VerbClear     Verb = "clear"
	VerbPressKeys Verb = "press_keys"
	// VerbEnterCredential names the verb, not a secret: the credential's value
	// never appears in a journey document, which is the whole point of the verb.
	VerbEnterCredential Verb = "enter_credential" //nolint:gosec // a verb name

	// Perception.
	VerbObserve Verb = "observe"
	VerbRead    Verb = "read"
	VerbCapture Verb = "capture"

	// Synchronisation.
	VerbPause Verb = "pause"
)

// param is one step parameter, as a bit so a verb's accepted set is a mask and
// "parameters this verb does not take" is one bit operation rather than a list of
// hand-written checks.
type param uint32

const (
	pTarget param = 1 << iota
	pApp
	pWindow
	pURL
	pValue
	pText
	pKeys
	pCredential
	pLabel
	pDirection
	pAmount
	pSeconds
	pSubmit
	pScope
	pPosition
	pSize
)

// paramNames renders a mask for a validation message, in declaration order so the
// message is stable.
var paramNames = []struct {
	bit  param
	name string
}{
	{pTarget, "target"},
	{pApp, "app"},
	{pWindow, "window"},
	{pURL, "url"},
	{pValue, "value"},
	{pText, "text"},
	{pKeys, "keys"},
	{pCredential, "credential"},
	{pLabel, "label"},
	{pDirection, "direction"},
	{pAmount, "amount"},
	{pSeconds, "seconds"},
	{pSubmit, "submit"},
	{pScope, "scope"},
	{pPosition, "position"},
	{pSize, "size"},
}

// names lists the parameters set in a mask.
func (p param) names() []string {
	var out []string
	for _, n := range paramNames {
		if p&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return out
}

// verbSpec is everything the vocabulary knows about one verb: the parameters it
// takes, and the plan target it derives (taxonomy §7). A zero kind means the verb
// touches nothing derivable — pause is the only one.
type verbSpec struct {
	required param
	optional param
	kind     plan.TargetKind
	reach    plan.TargetVerb
}

// accepts is every parameter the verb may carry.
func (s verbSpec) accepts() param { return s.required | s.optional }

// verbs is the closed verb set. Adding a verb means adding a row here, a lowering
// in compile.go, and a line in the taxonomy — and the tests fail until all three
// agree.
var verbs = map[Verb]verbSpec{
	VerbOpenApp:      {required: pApp, kind: plan.KindUI, reach: plan.VerbCreate},
	VerbFocusWindow:  {required: pWindow, kind: plan.KindUI, reach: plan.VerbInvoke},
	VerbResizeWindow: {required: pWindow, optional: pPosition | pSize, kind: plan.KindUI, reach: plan.VerbInvoke},
	VerbCloseWindow:  {required: pWindow, kind: plan.KindUI, reach: plan.VerbDelete},

	VerbNavigate: {required: pURL, kind: plan.KindHost, reach: plan.VerbReach},
	VerbScroll:   {required: pDirection, optional: pTarget | pAmount, kind: plan.KindUI, reach: plan.VerbRead},

	VerbClick:       {required: pTarget, kind: plan.KindUI, reach: plan.VerbInvoke},
	VerbDoubleClick: {required: pTarget, kind: plan.KindUI, reach: plan.VerbInvoke},
	VerbRightClick:  {required: pTarget, kind: plan.KindUI, reach: plan.VerbInvoke},
	VerbHover:       {required: pTarget, kind: plan.KindUI, reach: plan.VerbRead},

	VerbInvoke:   {required: pTarget, kind: plan.KindUI, reach: plan.VerbInvoke},
	VerbToggle:   {required: pTarget, kind: plan.KindUI, reach: plan.VerbWrite},
	VerbSelect:   {required: pTarget, kind: plan.KindUI, reach: plan.VerbWrite},
	VerbExpand:   {required: pTarget, kind: plan.KindUI, reach: plan.VerbInvoke},
	VerbCollapse: {required: pTarget, kind: plan.KindUI, reach: plan.VerbInvoke},

	VerbSetValue: {required: pTarget | pValue, kind: plan.KindUI, reach: plan.VerbWrite},
	VerbTypeText: {required: pText, optional: pTarget | pSubmit, kind: plan.KindUI, reach: plan.VerbWrite},
	VerbClear:    {required: pTarget, kind: plan.KindUI, reach: plan.VerbWrite},
	// press_keys derives execute, not invoke: win+r is arbitrary reach into the
	// shell, which is why Shortcut carries DestructiveHint. Taxonomy §3.2.
	VerbPressKeys: {required: pKeys, kind: plan.KindUI, reach: plan.VerbExecute},
	// The target is optional because injection into the already-focused field is
	// legitimate — a recorded draft where the human tabbed into the password box
	// has no click to attach a selector to, and the Credentials tool clicks a
	// target only when it is given one.
	VerbEnterCredential: {
		required: pCredential, optional: pTarget | pSubmit,
		kind: plan.KindUI, reach: plan.VerbWrite,
	},

	VerbObserve: {optional: pScope, kind: plan.KindUI, reach: plan.VerbRead},
	VerbRead:    {required: pTarget, kind: plan.KindUI, reach: plan.VerbRead},
	VerbCapture: {required: pLabel, kind: plan.KindUI, reach: plan.VerbRead},

	VerbPause: {required: pSeconds},
}

// Known reports whether the verb is one this build compiles.
func (v Verb) Known() bool {
	_, ok := verbs[v]
	return ok
}

// ValueType is the type of the value a subject reads. It is what decides which
// operators are legal (taxonomy §5.3).
type ValueType string

const (
	TypeText      ValueType = "text"
	TypeNumber    ValueType = "number"
	TypeBoolean   ValueType = "boolean"
	TypeExistence ValueType = "existence"
)

// Subject names what an assertion reads.
type Subject string

const (
	SubjectScreenText         Subject = "screen.text"
	SubjectWindowTitle        Subject = "window.title"
	SubjectWindow             Subject = "window"
	SubjectElement            Subject = "element"
	SubjectElementName        Subject = "element.name"
	SubjectElementValue       Subject = "element.value"
	SubjectElementControlType Subject = "element.control_type"
	SubjectElementEnabled     Subject = "element.enabled"
	SubjectElementChecked     Subject = "element.checked"
	SubjectElementSelected    Subject = "element.selected"
	SubjectElementFocused     Subject = "element.focused"
	SubjectElementCount       Subject = "element.count"
	SubjectResultText         Subject = "result.text"
)

type subjectSpec struct {
	valueType ValueType
	// needsTarget marks a subject that reads a specific element or window, so an
	// assertion using it must carry a selector.
	needsTarget bool
	// countsMatches marks the one subject for which a multiply-matching selector is
	// the question rather than an error, so unique-occurrence checking is skipped.
	countsMatches bool
}

var subjects = map[Subject]subjectSpec{
	SubjectScreenText:         {valueType: TypeText},
	SubjectWindowTitle:        {valueType: TypeText},
	SubjectWindow:             {valueType: TypeExistence, needsTarget: true},
	SubjectElement:            {valueType: TypeExistence, needsTarget: true},
	SubjectElementName:        {valueType: TypeText, needsTarget: true},
	SubjectElementValue:       {valueType: TypeText, needsTarget: true},
	SubjectElementControlType: {valueType: TypeText, needsTarget: true},
	SubjectElementEnabled:     {valueType: TypeBoolean, needsTarget: true},
	SubjectElementChecked:     {valueType: TypeBoolean, needsTarget: true},
	SubjectElementSelected:    {valueType: TypeBoolean, needsTarget: true},
	SubjectElementFocused:     {valueType: TypeBoolean, needsTarget: true},
	SubjectElementCount:       {valueType: TypeNumber, needsTarget: true, countsMatches: true},
	SubjectResultText:         {valueType: TypeText},
}

// Known reports whether the subject is one this build evaluates.
func (s Subject) Known() bool {
	_, ok := subjects[s]
	return ok
}

// Operator is the comparison an assertion applies.
type Operator string

const (
	OpIs             Operator = "is"
	OpIsNot          Operator = "is_not"
	OpContains       Operator = "contains"
	OpDoesNotContain Operator = "does_not_contain"
	OpStartsWith     Operator = "starts_with"
	OpEndsWith       Operator = "ends_with"
	OpMatches        Operator = "matches"
	OpDoesNotMatch   Operator = "does_not_match"
	OpIsEmpty        Operator = "is_empty"
	OpIsNotEmpty     Operator = "is_not_empty"
	OpIsOneOf        Operator = "is_one_of"
	OpIsNotOneOf     Operator = "is_not_one_of"
	OpIsTrue         Operator = "is_true"
	OpIsFalse        Operator = "is_false"
	OpExists         Operator = "exists"
	OpDoesNotExist   Operator = "does_not_exist"
	OpGreaterThan    Operator = "greater_than"
	OpGreaterOrEqual Operator = "greater_or_equal"
	OpLessThan       Operator = "less_than"
	OpLessOrEqual    Operator = "less_or_equal"
)

// operand says what shape of `expected` an operator takes. An operator taking
// none rejects an `expected` outright rather than ignoring it: silently dropping
// a field the author wrote is how a document comes to mean something other than
// it says.
type operand int

const (
	operandNone operand = iota
	operandScalar
	operandList
)

type operatorSpec struct {
	// types is the set of value types this operator may be applied to. It is the
	// matrix of taxonomy §5.3, read by column.
	types   []ValueType
	operand operand
	// regex marks an operator whose expected value is an RE2 pattern, compiled at
	// validation time so a bad pattern fails offline rather than mid-run.
	regex bool
}

var operators = map[Operator]operatorSpec{
	OpIs:             {types: []ValueType{TypeText, TypeNumber, TypeBoolean}, operand: operandScalar},
	OpIsNot:          {types: []ValueType{TypeText, TypeNumber, TypeBoolean}, operand: operandScalar},
	OpContains:       {types: []ValueType{TypeText}, operand: operandScalar},
	OpDoesNotContain: {types: []ValueType{TypeText}, operand: operandScalar},
	OpStartsWith:     {types: []ValueType{TypeText}, operand: operandScalar},
	OpEndsWith:       {types: []ValueType{TypeText}, operand: operandScalar},
	OpMatches:        {types: []ValueType{TypeText}, operand: operandScalar, regex: true},
	OpDoesNotMatch:   {types: []ValueType{TypeText}, operand: operandScalar, regex: true},
	OpIsEmpty:        {types: []ValueType{TypeText}, operand: operandNone},
	OpIsNotEmpty:     {types: []ValueType{TypeText}, operand: operandNone},
	OpIsOneOf:        {types: []ValueType{TypeText, TypeNumber}, operand: operandList},
	OpIsNotOneOf:     {types: []ValueType{TypeText, TypeNumber}, operand: operandList},
	OpIsTrue:         {types: []ValueType{TypeBoolean}, operand: operandNone},
	OpIsFalse:        {types: []ValueType{TypeBoolean}, operand: operandNone},
	OpExists:         {types: []ValueType{TypeExistence}, operand: operandNone},
	OpDoesNotExist:   {types: []ValueType{TypeExistence}, operand: operandNone},
	OpGreaterThan:    {types: []ValueType{TypeNumber}, operand: operandScalar},
	OpGreaterOrEqual: {types: []ValueType{TypeNumber}, operand: operandScalar},
	OpLessThan:       {types: []ValueType{TypeNumber}, operand: operandScalar},
	OpLessOrEqual:    {types: []ValueType{TypeNumber}, operand: operandScalar},
}

// Known reports whether the operator is one this build evaluates.
func (o Operator) Known() bool {
	_, ok := operators[o]
	return ok
}

// appliesTo reports whether the operator is legal for a value type — one cell of
// the matrix.
func (s operatorSpec) appliesTo(t ValueType) bool {
	return slices.Contains(s.types, t)
}

// NameMatch is how a selector's name is compared. It qualifies name and belongs
// only with it: an automation_id is an identifier, matched exactly, with nothing
// to relax.
type NameMatch string

const (
	// MatchExact is the default. The exact-then-substring fallback it replaces is
	// what let a selector for "Save" resolve to "Save As…" on any screen with no
	// exact match — and pass, having acted on the wrong control.
	MatchExact    NameMatch = "exact"
	MatchContains NameMatch = "contains"
	MatchMatches  NameMatch = "matches"
)

// Known reports whether the name-match mode is one this build resolves.
func (m NameMatch) Known() bool {
	switch m {
	case MatchExact, MatchContains, MatchMatches:
		return true
	default:
		return false
	}
}

// Scope is how wide a selector searches.
type Scope string

const (
	ScopeForeground Scope = "foreground"
	ScopeAnyWindow  Scope = "any_window"
)

// Known reports whether the scope is one this build resolves.
func (s Scope) Known() bool {
	switch s {
	case ScopeForeground, ScopeAnyWindow:
		return true
	default:
		return false
	}
}

// Wait bounds and defaults, matching the WaitFor tool's own limits so a journey
// cannot ask for a poll the executor will silently clamp.
const (
	DefaultWaitTimeout  = 10.0
	MaxWaitTimeout      = 120.0
	DefaultWaitInterval = 0.4
	MinWaitInterval     = 0.05
)

// MaxPatternLength caps a regex. RE2 does not backtrack, so a pathological
// pattern cannot hang a run; the cap is about a human being able to review it.
const MaxPatternLength = 512

// MaxPauseSeconds bounds a fixed sleep, matching the Wait tool's clamp.
const MaxPauseSeconds = 60.0
