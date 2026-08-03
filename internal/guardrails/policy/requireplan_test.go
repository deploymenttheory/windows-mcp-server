package policy

import (
	"strings"
	"testing"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/signals"
)

func TestRequiresPlanGatesBySelector(t *testing.T) {
	e, _ := newTestEngine(t, `{"version":1,"mode":"enforce","require_plan":[{"tool":"PowerShell"}]}`,
		map[string]signals.Status{})

	if !e.RequiresPlan(e.SubjectForTool("tools/call", "PowerShell")) {
		t.Error("PowerShell should require a plan")
	}
	if e.RequiresPlan(e.SubjectForTool("tools/call", "Snapshot")) {
		t.Error("Snapshot is not gated and should not require a plan")
	}
	// A startup subject is never plan-gated.
	if e.RequiresPlan(StartupSubject()) {
		t.Error("the startup subject must never require a plan")
	}
}

func TestRequiresPlanExemptsPlanningToolset(t *testing.T) {
	// A wildcard gate would otherwise deadlock — you could not call Plan to make a
	// plan — so the planning toolset is exempt.
	e, _ := newTestEngine(t, `{"version":1,"mode":"enforce","require_plan":[{"toolset":"*"}]}`,
		map[string]signals.Status{})

	planning := Subject{Scope: ScopeCall, Method: "tools/call", Facts: ToolFacts{Name: "Plan", Toolset: "planning"}}
	if e.RequiresPlan(planning) {
		t.Error("planning tools must be exempt from require_plan")
	}
	if !e.RequiresPlan(e.SubjectForTool("tools/call", "Snapshot")) {
		t.Error("a wildcard gate should still cover an ordinary tool")
	}
}

func TestRequirePlanValidation(t *testing.T) {
	mustParse := func(s string) *Policy {
		p, err := Parse([]byte(s))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return p
	}

	if err := mustParse(`{"version":1,"require_plan":[{}]}`).Validate(nil); err == nil ||
		!strings.Contains(err.Error(), "selects nothing") {
		t.Errorf("a require_plan selector that names nothing should be rejected, got %v", err)
	}
	if err := mustParse(`{"version":1,"require_plan":[{"scope":"startup","tool":"X"}]}`).Validate(nil); err == nil ||
		!strings.Contains(err.Error(), "call-scoped") {
		t.Errorf("a startup-scoped require_plan should be rejected, got %v", err)
	}
	if err := mustParse(`{"version":1,"require_plan":[{"annotation":"destructive"}]}`).Validate(nil); err != nil {
		t.Errorf("a valid require_plan should pass, got %v", err)
	}
}
