// Package journeys is the declarative model of a user journey: a named sequence
// of UI actions, each with assertions about the resulting screen and evidence to
// capture. A journey is authored once and run deterministically — it is how a UI
// regression or an acceptance test is expressed as code rather than a prose script.
//
// A journey is written in a closed vocabulary of verbs, selectors, subjects and
// operators, specified normatively in docs/journey-taxonomy.md and expressed as
// data in vocabulary.go. It names no MCP tool: Compile lowers each verb to the
// tool call that expresses it, so the tool surface can change without invalidating
// a checked-in suite, and so a journey's reach can be derived from the document
// rather than declared by it.
//
// A journey compiles to a plan.Document (see Compile), so it runs through the same
// executor that Apply uses: every step is evaluated by the policy engine, audited,
// and fail-stopped on the first failure. An assertion is compiled to a call of the
// Assert tool, so a failed assertion is a failed step — the journey stops and
// reports it, exactly as a test runner would.
//
// This package is a leaf: it depends only on the plan model and the standard
// library, and holds no MCP or Windows types. That is what lets `journey validate`
// check a document completely — verbs, parameters, selectors, the operator
// matrix — offline, in CI, on any platform. The live run lives in internal/winmcp,
// which has the engine and the tool surface.
package journeys

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// SchemaVersion is the journey document version this build understands.
//
// Version 1 is not accepted and there is no conversion. A v1 step named an MCP
// tool and carried an untyped argument map, which is precisely what this schema
// replaces; converting one mechanically would produce a document that still could
// not be checked.
const SchemaVersion = 2

// Errors surfaced by loading and validation, distinct so a caller can report a
// precise cause.
var (
	ErrJourneyVersion  = errors.New("unsupported journey version")
	ErrInvalidJourney  = errors.New("invalid journey")
	ErrUnknownVerb     = errors.New("unknown verb")
	ErrUnknownSubject  = errors.New("unknown assertion subject")
	ErrUnknownOperator = errors.New("unknown assertion operator")
	ErrBadOccurrence   = errors.New(`occurrence must be "unique", "first", or a non-negative integer`)
)

// Journey is a named, ordered sequence of UI steps with assertions and evidence.
type Journey struct {
	Version     int    `json:"version"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Steps       []Step `json:"steps"`
	// ExpectedEvidence lists evidence labels the journey is expected to produce, so
	// a reviewer can state up front what artifacts a passing run must contain. Every
	// entry must be captured by some step, or the expectation can never be met — and
	// a run that does not actually capture one fails, even if every assertion passed.
	ExpectedEvidence []string `json:"expected_evidence,omitempty"`
}

// Step is one action, the assertions that must hold after it, and any evidence to
// capture at that point.
//
// The action's parameters are typed and flat rather than an argument bag: each
// verb declares which of them it takes (see verbs in vocabulary.go), so passing
// `value` to `press_keys` is a validation error offline, before anything runs. A
// parameter left at its zero value counts as absent, which is why every optional
// parameter is one whose zero value means "not asked for".
type Step struct {
	Name string `json:"name,omitempty"`
	Verb Verb   `json:"verb"`

	// Target selects the element or window the verb acts on.
	Target *Selector `json:"target,omitempty"`

	App        string  `json:"app,omitempty"`        // open_app
	Window     string  `json:"window,omitempty"`     // focus_window, resize_window, close_window
	URL        string  `json:"url,omitempty"`        // navigate
	Value      string  `json:"value,omitempty"`      // set_value
	Text       string  `json:"text,omitempty"`       // type_text
	Keys       string  `json:"keys,omitempty"`       // press_keys
	Credential string  `json:"credential,omitempty"` // enter_credential
	Label      string  `json:"label,omitempty"`      // capture
	Direction  string  `json:"direction,omitempty"`  // scroll
	Amount     int     `json:"amount,omitempty"`     // scroll
	Seconds    float64 `json:"seconds,omitempty"`    // pause
	Submit     bool    `json:"submit,omitempty"`     // type_text, enter_credential
	Scope      Scope   `json:"scope,omitempty"`      // observe
	Position   []int   `json:"position,omitempty"`   // resize_window
	Size       []int   `json:"size,omitempty"`       // resize_window

	// Assertions lists conditions checked after the action; a failed one fails the
	// step. Named to match the plural-noun convention every other array field uses.
	Assertions []Assertion `json:"assertions,omitempty"`
	// Evidence lists captions for evidence to capture after the action.
	Evidence []string `json:"evidence,omitempty"`
}

// params returns the mask of parameters this step actually carries. A zero value
// counts as absent, so `submit: false` and an omitted `submit` are the same
// document — which is what they mean.
func (s Step) params() param {
	var p param
	set := func(cond bool, bit param) {
		if cond {
			p |= bit
		}
	}
	set(s.Target != nil, pTarget)
	set(s.App != "", pApp)
	set(s.Window != "", pWindow)
	set(s.URL != "", pURL)
	set(s.Value != "", pValue)
	set(s.Text != "", pText)
	set(s.Keys != "", pKeys)
	set(s.Credential != "", pCredential)
	set(s.Label != "", pLabel)
	set(s.Direction != "", pDirection)
	set(s.Amount != 0, pAmount)
	set(s.Seconds != 0, pSeconds)
	set(s.Submit, pSubmit)
	set(s.Scope != "", pScope)
	set(len(s.Position) > 0, pPosition)
	set(len(s.Size) > 0, pSize)
	return p
}

// Selector names the UI element or window a verb acts on. Exactly one of
// AutomationID, Name or Point identifies it; ControlType may narrow any of them.
//
// The three identifying keys are a stability ladder (taxonomy §4.1):
// AutomationID is developer-assigned and survives translation, Name survives
// relayout, and Point survives nothing. A recorder picks the highest rung the
// application offers.
type Selector struct {
	AutomationID string `json:"automation_id,omitempty"`
	Name         string `json:"name,omitempty"`
	ControlType  string `json:"control_type,omitempty"`
	// NameMatch qualifies Name and belongs only with it. Empty means MatchExact.
	NameMatch NameMatch `json:"name_match,omitempty"`
	// Occurrence decides what happens when the selector matches more than one
	// element. Empty means OccurrenceUnique, under which ambiguity is a failure.
	//
	// omitzero, not omitempty: omitempty has no effect on a struct field, so the
	// zero value would be written out as an occurrence of "" and fail to parse back
	// — which is exactly what a recorded journey does on its round trip to disk.
	Occurrence Occurrence `json:"occurrence,omitzero"`
	// Point is a coordinate target: legal, because a recorder must be able to
	// capture a control with no name, and marked non-durable wherever it appears.
	Point []int `json:"point,omitempty"`
	// Scope is how wide the search is. Empty means ScopeForeground.
	Scope Scope `json:"scope,omitempty"`
}

// identifiers counts how many of the three identifying keys are set.
func (s *Selector) identifiers() int {
	n := 0
	for _, set := range []bool{s.AutomationID != "", s.Name != "", len(s.Point) > 0} {
		if set {
			n++
		}
	}
	return n
}

// OccurrenceMode is how a selector resolves multiple matches.
type OccurrenceMode string

const (
	// OccurrenceUnique is the default: more than one match is a failure naming the
	// candidates, rather than a silent pick whose outcome depends on tree ordering.
	OccurrenceUnique OccurrenceMode = "unique"
	// OccurrenceFirst takes the first match, when an author means to.
	OccurrenceFirst OccurrenceMode = "first"
	// OccurrenceIndex takes a specific 0-based match.
	OccurrenceIndex OccurrenceMode = "index"
)

// Occurrence is a small union: the JSON is either "unique", "first", or an
// integer. It is a type rather than an `any` so the rest of the package reads a
// mode instead of type-switching on a decoded value.
type Occurrence struct {
	Mode  OccurrenceMode
	Index int
}

// Resolved returns the occurrence with its default applied.
func (o Occurrence) Resolved() Occurrence {
	if o.Mode == "" {
		return Occurrence{Mode: OccurrenceUnique}
	}
	return o
}

// UnmarshalJSON accepts "unique", "first", or a non-negative integer.
func (o *Occurrence) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		switch OccurrenceMode(s) {
		case OccurrenceUnique, OccurrenceFirst:
			o.Mode = OccurrenceMode(s)
			return nil
		default:
			return fmt.Errorf("%w: got %q", ErrBadOccurrence, s)
		}
	}
	var n int
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("%w: got %s", ErrBadOccurrence, b)
	}
	if n < 0 {
		return fmt.Errorf("%w: got %d", ErrBadOccurrence, n)
	}
	o.Mode, o.Index = OccurrenceIndex, n
	return nil
}

// MarshalJSON writes the mode name, or the bare index for OccurrenceIndex, so a
// document round-trips to the form it was written in.
func (o Occurrence) MarshalJSON() ([]byte, error) {
	switch o.Mode {
	case "":
		return []byte(`""`), nil
	case OccurrenceIndex:
		return []byte(strconv.Itoa(o.Index)), nil
	default:
		b, err := json.Marshal(string(o.Mode))
		if err != nil {
			return nil, fmt.Errorf("marshal occurrence: %w", err)
		}
		return b, nil
	}
}

// String renders an occurrence for a step label or a run record.
func (o Occurrence) String() string {
	r := o.Resolved()
	if r.Mode == OccurrenceIndex {
		return strconv.Itoa(r.Index)
	}
	return string(r.Mode)
}

// Assertion is one condition checked after a step, as subject × operator ×
// expected. A failed one fails the step, which stops the run — a journey is a
// test, so it stops at the first thing that is not true.
type Assertion struct {
	Subject  Subject   `json:"subject"`
	Target   *Selector `json:"target,omitempty"`
	Operator Operator  `json:"operator"`
	// Expected is the value compared against, typed by the subject: a string for a
	// text subject, a number for a numeric one, a bool for a boolean one, and an
	// array of those for is_one_of. An operator taking no operand rejects it.
	Expected any `json:"expected,omitempty"`
	// Message is a human description of what is being verified, carried through to
	// the assertion's PASS/FAIL line whether or not it polled.
	Message string `json:"message,omitempty"`
	// Wait turns a single evaluation into a polled one. Absent, the condition is
	// checked once.
	Wait *Wait `json:"wait,omitempty"`

	// Comparison modifiers, all defaulting off so behaviour is never implicit.
	IgnoreCase         bool `json:"ignore_case,omitempty"`
	Trim               bool `json:"trim,omitempty"`
	CollapseWhitespace bool `json:"collapse_whitespace,omitempty"`
}

// Wait is the poll budget for an assertion.
type Wait struct {
	// Timeout is the budget in seconds. Zero takes DefaultWaitTimeout.
	Timeout float64 `json:"timeout,omitempty"`
	// Interval is the poll period in seconds. Zero takes DefaultWaitInterval.
	Interval float64 `json:"interval,omitempty"`
}

// Resolved returns the wait with its defaults applied.
func (w *Wait) Resolved() Wait {
	out := Wait{Timeout: DefaultWaitTimeout, Interval: DefaultWaitInterval}
	if w == nil {
		return out
	}
	if w.Timeout > 0 {
		out.Timeout = w.Timeout
	}
	if w.Interval > 0 {
		out.Interval = w.Interval
	}
	return out
}

// Parse decodes a journey document, rejecting unknown fields so a typo in a key
// surfaces at load rather than being silently dropped.
func Parse(raw []byte) (Journey, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var j Journey
	if err := dec.Decode(&j); err != nil {
		return Journey{}, fmt.Errorf("parse journey: %w", err)
	}
	return j, nil
}

// stepLabel names a step for a message: its explicit name, or a positional label.
func stepLabel(s Step, i int) string {
	if s.Name != "" {
		return s.Name
	}
	if s.Verb != "" {
		return string(s.Verb)
	}
	return fmt.Sprintf("#%d", i)
}
