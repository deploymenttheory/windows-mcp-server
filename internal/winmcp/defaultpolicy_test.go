//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"testing"

	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy/policytest"
	"github.com/deploymenttheory/agentweave-harness/guardrails/signals"
	"github.com/deploymenttheory/mcp-server-core/runtime"
)

// TestServerDefaultPolicyIsAuditOnly is this repo's pin of the never-refuse
// default. The canonical TestDefaultPolicyIsAuditOnly lives with the policy
// package in agentweave-harness, and the load path in mcp-server-core, which
// means a release of either could in principle change the default and this
// server would only inherit the regression on the next dependency bump. This
// test makes that bump fail instead: it drives the server's own policy load
// path — the registry this server builds, no document — and asserts,
// behaviorally rather than by inspecting rules, that a destructive call is
// still admitted with every signal the default names failing.
func TestServerDefaultPolicyIsAuditOnly(t *testing.T) {
	reg := runtime.NewGuardrailRegistry(envNames, discardLogger())
	p, err := runtime.LoadPolicy("", reg, discardLogger())
	if err != nil {
		t.Fatalf("LoadPolicy with no document: %v", err)
	}

	if p.Mode != policy.ModeAuditOnly {
		t.Fatalf("default mode = %q, want %q", p.Mode, policy.ModeAuditOnly)
	}
	if p.Egress.Enabled {
		t.Error("default policy enables the egress proxy; the default must not alter the device's networking")
	}

	// Worst case the default can express: every signal it names is failing, and
	// the subject is a destructive execution primitive.
	states := map[string]signals.Status{}
	for _, id := range p.SignalIDs() {
		states[id] = signals.Fail
	}
	facts := policy.ToolFacts{Name: "PowerShell", Toolset: "shell", Destructive: true}
	eng := policytest.NewEngine(p, policytest.StaticIndex{"PowerShell": facts}, states)

	v := eng.Evaluate(context.Background(), policy.Subject{
		Scope:  policy.ScopeCall,
		Method: "tools/call",
		Facts:  facts,
	})
	if !v.Allowed() {
		t.Fatalf("default policy refused a call (severity %v); the default must never refuse", v.Severity)
	}
}
