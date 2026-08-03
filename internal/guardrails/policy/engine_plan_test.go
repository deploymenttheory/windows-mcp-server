package policy_test

import (
	"testing"
	"time"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy/policytest"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/signals"
)

var planIndex = policytest.StaticIndex{
	"Snapshot":   {Name: "Snapshot", Toolset: "screen", ReadOnly: true},
	"PowerShell": {Name: "PowerShell", Toolset: "shell", Destructive: true},
}

func TestEvaluatePlanAggregatesWorstStep(t *testing.T) {
	p := &policy.Policy{
		Version: 1, Mode: policy.ModeEnforcing,
		Signals: map[string]policy.SignalConfig{"run-context": {}},
		Rules: []policy.Rule{{
			Name:    "shell-deny",
			Match:   policy.Match{Tool: policy.StringSet{"PowerShell"}},
			Require: []string{"run-context"},
			OnFail:  policy.SeverityDeny,
		}},
	}

	// run-context fails, so the PowerShell step denies and the Snapshot step (no
	// matching rule) is allowed.
	e := policytest.NewEngine(p, planIndex, map[string]signals.Status{"run-context": signals.Fail})
	pv := e.EvaluatePlan(ctx, []policy.Subject{
		e.SubjectForTool("tools/call", "Snapshot"),
		e.SubjectForTool("tools/call", "PowerShell"),
	})

	if pv.Allowed() {
		t.Error("a plan containing a denied step must not be allowed")
	}
	if pv.Severity != policy.SeverityDeny {
		t.Errorf("plan severity = %v, want deny", pv.Severity)
	}
	if len(pv.Steps) != 2 {
		t.Fatalf("want 2 step verdicts, got %d", len(pv.Steps))
	}
	if !pv.Steps[0].Verdict.Allowed() {
		t.Error("the Snapshot step should be allowed")
	}
	if pv.Steps[1].Verdict.Allowed() {
		t.Error("the PowerShell step should be denied")
	}

	// A recovered device admits the whole plan, no restart.
	ok := policytest.NewEngine(p, planIndex, map[string]signals.Status{"run-context": signals.Pass})
	if !ok.EvaluatePlan(ctx, []policy.Subject{ok.SubjectForTool("tools/call", "PowerShell")}).Allowed() {
		t.Error("a healthy device should admit the plan")
	}
}

// TestEvaluatePlanDoesNotConsumeRateLimit pins that adjudicating a plan does not
// spend rate-limit budget: the plan has not run, so a five-step plan must not trip
// a max-one limit the way five real calls would.
func TestEvaluatePlanDoesNotConsumeRateLimit(t *testing.T) {
	p := &policy.Policy{
		Version: 1, Mode: policy.ModeEnforcing,
		Signals: map[string]policy.SignalConfig{"run-context": {}},
		Rules: []policy.Rule{{
			Name: "base", Match: policy.Match{Toolset: policy.StringSet{"*"}},
			Require: []string{"run-context"}, OnFail: policy.SeverityWarn,
		}},
		RateLimits: []policy.RateLimit{{
			Name: "burst", Match: policy.Match{Toolset: policy.StringSet{"*"}},
			Window: policy.Duration(time.Minute), Max: 1, OnExceed: policy.SeverityDeny,
		}},
	}
	e := policytest.NewEngine(p, planIndex, map[string]signals.Status{"run-context": signals.Pass})
	subj := e.SubjectForTool("tools/call", "Snapshot")

	pv := e.EvaluatePlan(ctx, []policy.Subject{subj, subj, subj, subj, subj})
	if !pv.Allowed() {
		t.Error("EvaluatePlan must not consume rate-limit budget; a 5-step plan should not trip a max-1 limit")
	}
}
