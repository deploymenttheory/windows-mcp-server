package enforce

import (
	"context"
	"testing"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/signals"
)

// fakeIndex stands in for the served tool manifest.
type fakeIndex map[string]policy.ToolFacts

func (f fakeIndex) Lookup(tool string) (policy.ToolFacts, bool) {
	facts, ok := f[tool]
	return facts, ok
}

var testIndex = fakeIndex{
	"Snapshot":   {Toolset: "screen", ReadOnly: true},
	"PowerShell": {Toolset: "shell", Destructive: true},
	"Registry":   {Toolset: "system", Destructive: true},
}

// newTestEngine builds an engine whose signals return fixed outcomes, so the
// enforcement tests exercise the middleware rather than the device probes.
//
// It is duplicated from the policy package's own harness rather than shared.
// Each package failing on its own is the point of splitting them; a shared
// test-support package would put them back in lockstep.
func newTestEngine(t *testing.T, policyJSON string, outcomes map[string]signals.Status) *policy.Engine {
	t.Helper()
	reg := signals.NewRegistry()
	ids := make([]string, 0, len(outcomes))
	for id, status := range outcomes {
		ids = append(ids, id)
		reg.Register(signals.Guardrail{ID: id, Check: fixedCheck(id, status)})
	}

	p, err := policy.Parse([]byte(policyJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(ids); err != nil {
		t.Fatalf("test policy is invalid: %v", err)
	}
	return policy.NewEngine(p, reg, testIndex, func() *signals.Env { return &signals.Env{} })
}

func fixedCheck(id string, status signals.Status) signals.CheckFunc {
	return func(context.Context, *signals.Env) signals.Result {
		return signals.Result{ID: id, Status: status}
	}
}
