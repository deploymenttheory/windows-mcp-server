// Package journeys is the declarative model of a user journey: a named sequence
// of UI actions, each with assertions about the resulting screen and evidence to
// capture. A journey is authored once and run deterministically — it is how a UI
// regression or an acceptance test is expressed as code rather than a prose script.
//
// A journey compiles to a plan.Document (see Compile), so it runs through the same
// executor that Apply uses: every step is evaluated by the policy engine, audited,
// and fail-stopped on the first failure. An assertion is compiled to a call of the
// Assert or WaitFor tool, so a failed assertion is a failed step — the journey
// stops and reports it, exactly as a test runner would.
//
// This package is a leaf: it depends only on the plan model and the standard
// library, and holds no MCP or Windows types, so the schema and the compilation
// are testable on any platform. The live run lives in internal/winmcp, which has
// the engine and the tool surface.
package journeys

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// SchemaVersion is the journey document version this build understands.
const SchemaVersion = 1

// Errors surfaced by loading and validation, distinct so a caller can report a
// precise cause.
var (
	ErrJourneyVersion   = errors.New("unsupported journey version")
	ErrInvalidJourney   = errors.New("invalid journey")
	ErrUnknownAssertion = errors.New("unknown assertion kind")
)

// Journey is a named, ordered sequence of UI steps with assertions and evidence.
type Journey struct {
	Version     int    `json:"version"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Steps       []Step `json:"steps"`
	// ExpectedEvidence lists evidence labels the journey is expected to produce, so
	// a reviewer can state up front what artifacts a passing run must contain. Every
	// entry must be captured by some step, or the expectation can never be met.
	ExpectedEvidence []string `json:"expected_evidence,omitempty"`
}

// Step is one UI action, the assertions that must hold after it, and any evidence
// to capture at that point.
type Step struct {
	Name string `json:"name,omitempty"`
	// Tool and Args are the action: an inventory tool name and its arguments, the
	// same shape a plan step carries.
	Tool string         `json:"tool"`
	Args map[string]any `json:"args,omitempty"`
	// Assertions lists conditions checked after the action; a failed one fails the
	// step. Named to match the plural-noun convention every other array field uses.
	Assertions []Assertion `json:"assertions,omitempty"`
	// Evidence lists captions for screenshots to capture after the action.
	Evidence []string `json:"evidence,omitempty"`
}

// AssertionKind names a condition to check after a step. Each maps to a call of
// the Assert tool (an immediate check) or the WaitFor tool (a polled check).
type AssertionKind string

// The kinds come in two symmetric families. An immediate kind checks the screen
// once; its value is exactly the Assert tool's condition name. A polled kind waits
// for that same condition to hold, and its value is the immediate name with a
// "wait_" prefix. text_absent has no polled form — WaitFor cannot wait for a thing
// to not be there — so it is the one immediate kind without a "wait_" twin.
const (
	// AssertTextPresent passes when the UI-tree text contains Target.
	AssertTextPresent AssertionKind = "text_present"
	// AssertTextAbsent passes when the UI-tree text does not contain Target.
	AssertTextAbsent AssertionKind = "text_absent"
	// AssertElementPresent passes when an interactive element's name contains Target.
	AssertElementPresent AssertionKind = "element_present"
	// AssertWindowActive passes when the foreground window title contains Target.
	AssertWindowActive AssertionKind = "window_active"
	// AssertWaitTextPresent polls until the UI-tree text contains Target (or times out).
	AssertWaitTextPresent AssertionKind = "wait_text_present"
	// AssertWaitElementPresent polls until an element's name contains Target.
	AssertWaitElementPresent AssertionKind = "wait_element_present"
	// AssertWaitWindowActive polls until the foreground window title contains Target.
	AssertWaitWindowActive AssertionKind = "wait_window_active"
)

// isWait reports whether a kind is a polled (WaitFor) assertion rather than an
// immediate (Assert) one.
func (k AssertionKind) isWait() bool {
	switch k {
	case AssertWaitTextPresent, AssertWaitElementPresent, AssertWaitWindowActive:
		return true
	default:
		return false
	}
}

// known reports whether the kind is one this build compiles.
func (k AssertionKind) known() bool {
	switch k {
	case AssertTextPresent, AssertTextAbsent, AssertElementPresent, AssertWindowActive,
		AssertWaitTextPresent, AssertWaitElementPresent, AssertWaitWindowActive:
		return true
	default:
		return false
	}
}

// Assertion is one condition checked after a step.
type Assertion struct {
	Kind AssertionKind `json:"kind"`
	// Target is the text, element name, or window-title substring to look for.
	// Every assertion kind needs one.
	Target string `json:"target"`
	// Timeout is the poll budget in seconds for a wait_for_* kind; ignored for the
	// immediate kinds. Zero lets the WaitFor tool apply its default.
	Timeout int `json:"timeout,omitempty"`
	// Message is an optional human description of what is being verified, surfaced
	// in the assertion's PASS/FAIL line.
	Message string `json:"message,omitempty"`
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

// Validate checks the journey is well-formed: a supported version, a name, at
// least one step, every step naming a tool, every assertion a known kind with a
// target, and every expected-evidence label actually produced by some step.
//
// It reports every problem at once, so an author fixing a file does not discover
// them one run at a time.
func (j Journey) Validate() error {
	if j.Version != SchemaVersion {
		return fmt.Errorf("%w: got %d, want %d", ErrJourneyVersion, j.Version, SchemaVersion)
	}

	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	if strings.TrimSpace(j.Name) == "" {
		add("journey has no name")
	}
	if len(j.Steps) == 0 {
		add("journey has no steps, so it verifies nothing")
	}

	produced := map[string]bool{}
	for i, s := range j.Steps {
		if strings.TrimSpace(s.Tool) == "" {
			add("step %d (%s): no tool named", i, stepLabel(s, i))
		}
		for a, as := range s.Assertions {
			if !as.Kind.known() {
				add("%v: step %d assertion %d has kind %q", ErrUnknownAssertion, i, a, as.Kind)
				continue
			}
			if strings.TrimSpace(as.Target) == "" {
				add("step %d assertion %d (%s): needs a target", i, a, as.Kind)
			}
			if as.Timeout < 0 {
				add("step %d assertion %d (%s): timeout must not be negative", i, a, as.Kind)
			}
			if as.Timeout > 0 && !as.Kind.isWait() {
				add("step %d assertion %d (%s): timeout is only meaningful for a wait_for_* kind", i, a, as.Kind)
			}
		}
		for _, label := range s.Evidence {
			produced[label] = true
		}
	}
	for _, want := range j.ExpectedEvidence {
		if !produced[want] {
			add("expected_evidence %q is never captured by any step", want)
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("%w:\n  - %s", ErrInvalidJourney, strings.Join(problems, "\n  - "))
	}
	return nil
}

// stepLabel names a step for a message: its explicit name, or a positional label.
func stepLabel(s Step, i int) string {
	if s.Name != "" {
		return s.Name
	}
	if s.Tool != "" {
		return s.Tool
	}
	return fmt.Sprintf("#%d", i)
}
