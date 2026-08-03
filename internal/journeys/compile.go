package journeys

import (
	"fmt"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/plan"
)

// The tools an assertion or an evidence capture compiles to. They are read-only
// inventory tools; a journey that uses assertions therefore needs the testing
// toolset served, which the runner selects.
const (
	toolAssert          = "Assert"
	toolWaitFor         = "WaitFor"
	toolCaptureEvidence = "CaptureEvidence"
)

// Compile turns a validated journey into a plan.Document: each step becomes an
// action step, followed by one step per assertion (a call to Assert or WaitFor)
// and one per evidence capture (a call to CaptureEvidence).
//
// The result is an ordinary plan, so it runs through the same executor Apply uses:
// every step is policy-evaluated, audited as plan.step, and fail-stopped on the
// first failure. A failed assertion is an Assert/WaitFor tool error — a failed
// step — so the journey stops there, which is exactly a test runner's behaviour.
//
// sessionID is stamped onto the document so its audit and any evidence bundle tie
// back to the run; it does not affect the plan id, which is content-derived.
func Compile(j Journey, sessionID string) (plan.Document, error) {
	if err := j.Validate(); err != nil {
		return plan.Document{}, err
	}

	var steps []plan.Step
	for i, s := range j.Steps {
		steps = append(steps, plan.Step{
			Name: actionName(s, i),
			Tool: s.Tool,
			Args: s.Args,
		})
		for a, as := range s.Assertions {
			ps, err := compileAssertion(as, i, a)
			if err != nil {
				return plan.Document{}, err
			}
			steps = append(steps, ps)
		}
		for _, label := range s.Evidence {
			steps = append(steps, plan.Step{
				Name: "evidence: " + label,
				Tool: toolCaptureEvidence,
				Args: map[string]any{"label": label},
			})
		}
	}

	doc := plan.Document{
		Version:   plan.SchemaVersion,
		SessionID: sessionID,
		Steps:     steps,
	}
	withID, err := doc.WithID()
	if err != nil {
		return plan.Document{}, fmt.Errorf("compute plan id: %w", err)
	}
	return withID, nil
}

// compileAssertion maps one assertion to the plan step that checks it.
func compileAssertion(as Assertion, stepIdx, assertIdx int) (plan.Step, error) {
	name := fmt.Sprintf("assert[%d.%d]: %s", stepIdx, assertIdx, assertDescription(as))
	switch as.Kind {
	case AssertTextPresent:
		return assertStep(name, "text_present", as), nil
	case AssertTextAbsent:
		return assertStep(name, "text_absent", as), nil
	case AssertElementPresent:
		return assertStep(name, "element_present", as), nil
	case AssertWindowActive:
		return windowAssertStep(name, "window_active", as), nil
	case AssertWaitTextPresent:
		return waitStep(name, "text_exists", as), nil
	case AssertWaitElementPresent:
		return waitStep(name, "element_exists", as), nil
	case AssertWaitWindowActive:
		return waitWindowStep(name, "active_window", as), nil
	default:
		return plan.Step{}, fmt.Errorf("%w: %q", ErrUnknownAssertion, as.Kind)
	}
}

// assertStep builds an Assert call keyed on the tree/element text.
func assertStep(name, condition string, as Assertion) plan.Step {
	args := map[string]any{"condition": condition, "text": as.Target}
	if as.Message != "" {
		args["message"] = as.Message
	}
	return plan.Step{Name: name, Tool: toolAssert, Args: args}
}

// windowAssertStep builds an Assert call keyed on the window title.
func windowAssertStep(name, condition string, as Assertion) plan.Step {
	args := map[string]any{"condition": condition, "window_name": as.Target}
	if as.Message != "" {
		args["message"] = as.Message
	}
	return plan.Step{Name: name, Tool: toolAssert, Args: args}
}

// waitStep builds a WaitFor call keyed on the tree/element text.
func waitStep(name, condition string, as Assertion) plan.Step {
	args := map[string]any{"condition": condition, "text": as.Target}
	if as.Timeout > 0 {
		args["timeout"] = as.Timeout
	}
	return plan.Step{Name: name, Tool: toolWaitFor, Args: args}
}

// waitWindowStep builds a WaitFor call keyed on the window title.
func waitWindowStep(name, condition string, as Assertion) plan.Step {
	args := map[string]any{"condition": condition, "window_name": as.Target}
	if as.Timeout > 0 {
		args["timeout"] = as.Timeout
	}
	return plan.Step{Name: name, Tool: toolWaitFor, Args: args}
}

// actionName labels the action step: the journey step's name, else its tool.
func actionName(s Step, i int) string {
	if s.Name != "" {
		return s.Name
	}
	return fmt.Sprintf("step %d: %s", i, s.Tool)
}

// assertDescription renders an assertion compactly for a step name.
func assertDescription(as Assertion) string {
	if as.Message != "" {
		return as.Message
	}
	return string(as.Kind) + " " + as.Target
}
