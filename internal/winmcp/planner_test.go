//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/enforce"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/plan"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy/policytest"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/signals"
)

// fakePlanApprover returns a fixed outcome for every step it adjudicates.
type fakePlanApprover struct {
	outcome enforce.Outcome
	calls   int
}

func (f *fakePlanApprover) Await(_ context.Context, _ enforce.ApprovalRequest) enforce.Decision {
	f.calls++
	return enforce.Decision{Outcome: f.outcome}
}

// holdStepPolicy gates FileSystem behind an hold rule that fires when
// run-context fails.
func holdStepPolicy() (*policy.Policy, map[string]signals.Status) {
	return &policy.Policy{
			Version: 1, Mode: policy.ModeEnforcing,
			Signals: map[string]policy.SignalConfig{"run-context": {}},
			Rules: []policy.Rule{{
				Name: "gate", Match: policy.Match{Tool: policy.StringSet{"FileSystem"}},
				Require: []string{"run-context"}, OnFail: policy.SeverityHold,
			}},
		},
		map[string]signals.Status{"run-context": signals.Fail}
}

type fakeRunner struct {
	served map[string]bool
	fail   map[string]bool
	calls  []string
}

func (f *fakeRunner) Has(tool string) bool { return f.served[tool] }

func (f *fakeRunner) Invoke(_ context.Context, tool string, _ json.RawMessage) (*mcp.CallToolResult, error) {
	f.calls = append(f.calls, tool)
	if f.fail[tool] {
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "boom"}}}, nil
	}
	return &mcp.CallToolResult{}, nil
}

type capDest struct {
	mu     sync.Mutex
	events []string
}

func (c *capDest) Write(e audit.AuditEntry) error {
	c.mu.Lock()
	c.events = append(c.events, e.Event)
	c.mu.Unlock()
	return nil
}
func (c *capDest) Flush() error { return nil }
func (c *capDest) Close() error { return nil }

func (c *capDest) has(event string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.events {
		if e == event {
			return true
		}
	}
	return false
}

var planTestIndex = policytest.StaticIndex{
	"Snapshot":   {Name: "Snapshot", Toolset: "screen", ReadOnly: true},
	"FileSystem": {Name: "FileSystem", Toolset: "filesystem", Destructive: true},
	"PowerShell": {Name: "PowerShell", Toolset: "shell", Destructive: true},
}

func newTestPlanner(t *testing.T, p *policy.Policy, states map[string]signals.Status, runner toolRunner, killed func() bool) (*planner, *capDest) {
	t.Helper()
	dest := &capDest{}
	log := audit.NewAuditLog(dest)
	engine := policytest.NewEngine(p, planTestIndex, states)
	if killed == nil {
		killed = func() bool { return false }
	}
	return newPlanner(engine, log, runner, killed), dest
}

func rawPlan(t *testing.T, steps ...plan.Step) []byte {
	t.Helper()
	raw, err := json.Marshal(plan.Document{Version: plan.SchemaVersion, Steps: steps})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func permissivePolicy() *policy.Policy {
	// No rules: every subject is admitted, so the planner logic is under test, not
	// the policy.
	return &policy.Policy{Version: 1, Mode: policy.ModeEnforcing}
}

func allServed() *fakeRunner {
	return &fakeRunner{
		served: map[string]bool{"Snapshot": true, "FileSystem": true, "PowerShell": true},
		fail:   map[string]bool{},
	}
}

// TestPlanningToolsetServesPlanAndApply also exercises that the two tools'
// schemas serialize into a real tools/list, since CaptureSurface runs one.
func TestPlanningToolsetServesPlanAndApply(t *testing.T) {
	surface, err := CaptureSurface(context.Background(), Config{Toolsets: []string{"planning"}})
	if err != nil {
		t.Fatalf("CaptureSurface: %v", err)
	}
	served := string(surface.ToolsListResult)
	for _, name := range []string{"Plan", "Apply"} {
		if !strings.Contains(served, `"`+name+`"`) {
			t.Errorf("%s should be served under the planning toolset", name)
		}
	}
}

func TestProposeThenApplyRunsEveryStep(t *testing.T) {
	runner := allServed()
	p, dest := newTestPlanner(t, permissivePolicy(), nil, runner, nil)

	raw := rawPlan(t,
		plan.Step{Name: "look", Tool: "Snapshot", Args: map[string]any{}},
		plan.Step{Name: "read", Tool: "FileSystem", Args: map[string]any{"mode": "read", "path": `C:\a`}},
	)

	prop, err := p.Propose(context.Background(), raw)
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !prop.Allowed || prop.PlanID == "" {
		t.Fatalf("expected an admitted plan with an id, got %+v", prop)
	}
	if !dest.has("plan.proposed") {
		t.Error("Propose should audit plan.proposed")
	}

	app, err := p.Apply(context.Background(), prop.PlanID)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(runner.calls) != 2 || runner.calls[0] != "Snapshot" || runner.calls[1] != "FileSystem" {
		t.Errorf("steps should run in order, got %v", runner.calls)
	}
	if !strings.Contains(app.Report, "2 completed") {
		t.Errorf("report should record 2 completed: %s", app.Report)
	}
	if !dest.has("plan.step") || !dest.has("plan.applied") {
		t.Error("Apply should audit plan.step and plan.applied")
	}
}

func TestApplyIsFailStop(t *testing.T) {
	runner := allServed()
	runner.fail["FileSystem"] = true // the second step errors
	p, _ := newTestPlanner(t, permissivePolicy(), nil, runner, nil)

	raw := rawPlan(t,
		plan.Step{Tool: "Snapshot", Args: map[string]any{}},
		plan.Step{Tool: "FileSystem", Args: map[string]any{"mode": "read", "path": `C:\a`}},
		plan.Step{Tool: "Snapshot", Args: map[string]any{}},
	)
	prop, _ := p.Propose(context.Background(), raw)
	app, _ := p.Apply(context.Background(), prop.PlanID)

	if len(runner.calls) != 2 {
		t.Errorf("apply must stop at the first failure; ran %v", runner.calls)
	}
	if !strings.Contains(app.Report, "1 completed") || !strings.Contains(app.Report, "1 failed") || !strings.Contains(app.Report, "1 skipped") {
		t.Errorf("report should be 1 completed, 1 failed, 1 skipped: %s", app.Report)
	}
}

func TestApplyRefusesWhenPostureDrifts(t *testing.T) {
	// PowerShell requires run-context; it passes at propose and fails at apply.
	pol := &policy.Policy{
		Version: 1, Mode: policy.ModeEnforcing,
		Signals: map[string]policy.SignalConfig{"run-context": {}},
		Rules: []policy.Rule{{
			Name: "shell", Match: policy.Match{Tool: policy.StringSet{"PowerShell"}},
			Require: []string{"run-context"}, OnFail: policy.SeverityDeny,
		}},
	}
	states := map[string]signals.Status{"run-context": signals.Pass}
	runner := allServed()
	p, dest := newTestPlanner(t, pol, states, runner, nil)

	raw := rawPlan(t, plan.Step{Tool: "PowerShell", Args: map[string]any{"command": "x"}})
	prop, err := p.Propose(context.Background(), raw)
	if err != nil || !prop.Allowed {
		t.Fatalf("plan should be admitted on a healthy device: %+v %v", prop, err)
	}

	states["run-context"] = signals.Fail // posture drifts before apply

	app, _ := p.Apply(context.Background(), prop.PlanID)
	if len(runner.calls) != 0 {
		t.Errorf("a stale plan must not run any step, ran %v", runner.calls)
	}
	if !strings.Contains(app.Report, "refused") || !dest.has("plan.refused") {
		t.Errorf("a stale plan should be refused and audited: %s", app.Report)
	}
}

func TestApplyAbandonsOnKill(t *testing.T) {
	runner := allServed()
	p, _ := newTestPlanner(t, permissivePolicy(), nil, runner, func() bool { return true })
	raw := rawPlan(t, plan.Step{Tool: "Snapshot", Args: map[string]any{}})
	prop, _ := p.Propose(context.Background(), raw)
	app, _ := p.Apply(context.Background(), prop.PlanID)
	if len(runner.calls) != 0 {
		t.Errorf("a tripped kill switch must abandon the apply, ran %v", runner.calls)
	}
	if !strings.Contains(app.Report, "abandoned") {
		t.Errorf("report should say abandoned: %s", app.Report)
	}
}

// TestApplyAdjudicatesHoldStepGranted: a plan step that hits an hold rule
// blocks on the same authoriser a direct call would, and runs only once approved —
// so Apply is never a way around dual control.
func TestApplyAdjudicatesHoldStepGranted(t *testing.T) {
	pol, states := holdStepPolicy()
	runner := allServed()
	p, dest := newTestPlanner(t, pol, states, runner, nil)
	fa := &fakePlanApprover{outcome: enforce.OutcomeApprove}
	p.withApprovals(fa, "sess", time.Second)

	raw := rawPlan(t, plan.Step{Tool: "FileSystem", Args: map[string]any{"mode": "read", "path": `C:\a`}})
	prop, err := p.Propose(context.Background(), raw)
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	app, err := p.Apply(context.Background(), prop.PlanID)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if fa.calls != 1 {
		t.Errorf("the hold step should have consulted the approver once, got %d", fa.calls)
	}
	if len(runner.calls) != 1 {
		t.Errorf("an approved step must run, ran %v", runner.calls)
	}
	if !dest.has("approval.requested") || !dest.has("approval.decided") {
		t.Error("Apply must audit the approval handshake for an hold step")
	}
	if !strings.Contains(app.Report, "1 completed") {
		t.Errorf("report should record the approved step ran: %s", app.Report)
	}
}

// TestApplyAdjudicatesHoldStepDenied: a denied step halts the plan, fail-closed.
func TestApplyAdjudicatesHoldStepDenied(t *testing.T) {
	pol, states := holdStepPolicy()
	runner := allServed()
	p, dest := newTestPlanner(t, pol, states, runner, nil)
	p.withApprovals(&fakePlanApprover{outcome: enforce.OutcomeDeny}, "sess", time.Second)

	raw := rawPlan(t, plan.Step{Tool: "FileSystem", Args: map[string]any{"mode": "read", "path": `C:\a`}})
	prop, _ := p.Propose(context.Background(), raw)
	app, _ := p.Apply(context.Background(), prop.PlanID)

	if len(runner.calls) != 0 {
		t.Errorf("a denied step must not run, ran %v", runner.calls)
	}
	if !strings.Contains(app.Report, "NOT APPROVED") {
		t.Errorf("report should record the step was not approved: %s", app.Report)
	}
	if !dest.has("approval.decided") {
		t.Error("a denied step must still audit the decision")
	}
}

// TestApplyHoldStepFailsClosedWithoutApprover: an hold step with no approver
// wired refuses rather than running unapproved.
func TestApplyHoldStepFailsClosedWithoutApprover(t *testing.T) {
	pol, states := holdStepPolicy()
	runner := allServed()
	p, _ := newTestPlanner(t, pol, states, runner, nil) // no withApprovals

	raw := rawPlan(t, plan.Step{Tool: "FileSystem", Args: map[string]any{"mode": "read", "path": `C:\a`}})
	prop, _ := p.Propose(context.Background(), raw)
	app, _ := p.Apply(context.Background(), prop.PlanID)

	if len(runner.calls) != 0 {
		t.Errorf("an hold step with no approver must not run, ran %v", runner.calls)
	}
	if !strings.Contains(app.Report, "NOT APPROVED") {
		t.Errorf("report should refuse the unapprovable step: %s", app.Report)
	}
}

func TestProposeRejectsBadPlans(t *testing.T) {
	p, _ := newTestPlanner(t, permissivePolicy(), nil, allServed(), nil)

	// A step that calls Apply cannot be planned.
	if _, err := p.Propose(context.Background(), rawPlan(t, plan.Step{Tool: "Apply", Args: map[string]any{"plan_id": "x"}})); err == nil {
		t.Error("a plan containing an Apply step should be rejected")
	}
	// A step naming an unserved tool is rejected up front.
	if _, err := p.Propose(context.Background(), rawPlan(t, plan.Step{Tool: "Nonexistent"})); err == nil {
		t.Error("a plan naming an unserved tool should be rejected")
	}
	// An unknown plan id cannot be applied.
	if _, err := p.Apply(context.Background(), "deadbeef"); err == nil {
		t.Error("applying an unknown plan id should error")
	}
}

// requirePlanPolicy gates FileSystem behind require_plan with every signal
// passing, so nothing else would refuse the apply.
func requirePlanPolicy() (*policy.Policy, map[string]signals.Status) {
	return &policy.Policy{
			Version: 1, Mode: policy.ModeEnforcing,
			Signals:     map[string]policy.SignalConfig{"run-context": {}},
			RequirePlan: []policy.Match{{Tool: policy.StringSet{"FileSystem"}}},
		},
		map[string]signals.Status{"run-context": signals.Pass}
}

// TestApplyPutsAPlanGatedPlanToAHuman is the property require_plan is supposed to
// have and did not.
//
// A direct call to a gated tool was refused with a message telling the model to
// submit a plan and Apply it -- which the model can do itself, unassisted, in two
// calls. Nothing else stood between proposing and executing, so on a healthy
// device the "preventive" tier prevented only the shape of the call. The plan is
// now put to the same authoriser a hold step uses, before any step runs.
func TestApplyPutsAPlanGatedPlanToAHuman(t *testing.T) {
	pol, states := requirePlanPolicy()
	runner := allServed()
	p, dest := newTestPlanner(t, pol, states, runner, nil)
	fa := &fakePlanApprover{outcome: enforce.OutcomeApprove}
	p.withApprovals(fa, "sess", time.Second)

	raw := rawPlan(t, plan.Step{Tool: "FileSystem", Args: map[string]any{"mode": "read", "path": `C:\a`}})
	prop, err := p.Propose(context.Background(), raw)
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if _, err := p.Apply(context.Background(), prop.PlanID); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if fa.calls != 1 {
		t.Errorf("a plan-gated apply must consult the approver once, got %d", fa.calls)
	}
	if !dest.has("approval.requested") || !dest.has("approval.decided") {
		t.Error("the plan-level approval handshake must be audited")
	}
	if len(runner.calls) != 1 {
		t.Errorf("an approved plan must run, ran %v", runner.calls)
	}
}

// TestApplyRefusesAPlanGatedPlanWithoutAnApprover fails closed. A require_plan
// rule is an operator saying these tools need review; no webhook means there is
// nobody to review, so the plan must not run. Proceeding would make the strictest
// configuration the one that silently checks nothing.
func TestApplyRefusesAPlanGatedPlanWithoutAnApprover(t *testing.T) {
	pol, states := requirePlanPolicy()
	runner := allServed()
	p, _ := newTestPlanner(t, pol, states, runner, nil) // no approver configured

	raw := rawPlan(t, plan.Step{Tool: "FileSystem", Args: map[string]any{"mode": "read", "path": `C:\a`}})
	prop, err := p.Propose(context.Background(), raw)
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	app, err := p.Apply(context.Background(), prop.PlanID)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Errorf("no step may run without an authoriser, ran %v", runner.calls)
	}
	if !strings.Contains(app.Report, "approvals webhook") {
		t.Errorf("the refusal should name the missing configuration: %s", app.Report)
	}
}

// TestApplyRefusesADeniedPlan: the authoriser's no halts the whole plan.
func TestApplyRefusesADeniedPlan(t *testing.T) {
	pol, states := requirePlanPolicy()
	runner := allServed()
	p, _ := newTestPlanner(t, pol, states, runner, nil)
	p.withApprovals(&fakePlanApprover{outcome: enforce.OutcomeDeny}, "sess", time.Second)

	raw := rawPlan(t, plan.Step{Tool: "FileSystem", Args: map[string]any{"mode": "read", "path": `C:\a`}})
	prop, err := p.Propose(context.Background(), raw)
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if _, err := p.Apply(context.Background(), prop.PlanID); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Errorf("a denied plan must not run any step, ran %v", runner.calls)
	}
}
