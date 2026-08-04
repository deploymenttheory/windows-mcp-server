//go:build windows && (amd64 || arm64)

package winmcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/enforce"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/plan"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy"
	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
	"github.com/deploymenttheory/windows-mcp-server/pkg/windows"
)

// inventoryRegistry runs a plan step by finding the tool in the served inventory
// and calling its handler directly, with the same dependencies the middleware
// injects. Plan and Apply are excluded from being step tools before we get here
// (see Propose), so this never recurses.
type inventoryRegistry struct {
	inv  *inventory.Inventory
	deps windows.ToolDependencies
}

func (r inventoryRegistry) Has(tool string) bool {
	for _, st := range r.inv.AvailableTools(context.Background()) {
		if st.Tool.Name == tool {
			return true
		}
	}
	return false
}

func (r inventoryRegistry) Invoke(
	ctx context.Context,
	tool string,
	rawArgs json.RawMessage,
) (*mcp.CallToolResult, error) {
	for _, st := range r.inv.AvailableTools(ctx) {
		if st.Tool.Name != tool {
			continue
		}
		res, err := st.Handler(r.deps)(
			windows.ContextWithDeps(ctx, r.deps),
			&mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: tool, Arguments: rawArgs}},
		)
		if err != nil {
			return res, fmt.Errorf("invoke %s: %w", tool, err)
		}
		return res, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrToolNotServed, tool)
}

// ErrPlanContainsPlanning reports a plan whose steps call Plan or Apply — a plan
// cannot nest or re-enter itself. ErrToolNotServed reports a step naming a tool
// the current surface does not serve.
var (
	ErrPlanContainsPlanning = errors.New("a plan cannot contain Plan or Apply steps")
	ErrToolNotServed        = errors.New("tool is not in the served surface")
	ErrUnknownPlan          = errors.New("unknown plan_id; call Plan first")
)

// toolRunner invokes a tool by name and reports whether one is served. The
// planner executes steps through it rather than re-entering MCP dispatch, so a
// plan step does not confuse rug-pull or circuit-breaker accounting; the winmcp
// implementation runs the real tool handler, and a fake backs the tests.
type toolRunner interface {
	Has(tool string) bool
	Invoke(ctx context.Context, tool string, rawArgs json.RawMessage) (*mcp.CallToolResult, error)
}

// planner is the plan-and-apply engine. It adjudicates a whole plan up front and,
// on Apply, runs it verbatim — the steps' arguments come from the stored plan, not
// from the Apply call, so within an Apply the executed operations are exactly the
// approved ones by construction. The only divergence surface is a direct call made
// outside a plan, which the audit chain records as a tool.call with no owning
// plan.step.
type planner struct {
	engine *policy.Engine
	audit  *audit.AuditLog
	runner toolRunner
	// killed reports whether containment has tripped, so an apply abandons its
	// remaining steps rather than pressing on through a kill.
	killed func() bool

	// approver adjudicates approve-disposition steps at execution time; nil unless
	// the policy configures an approvals webhook, in which case no hold rule can
	// exist (the policy is refused at load), so a nil approver here is never reached
	// by an hold step.
	approver        enforce.Approver
	sessionID       string
	approvalTimeout time.Duration

	mu    sync.Mutex
	store map[string]plan.Document
}

func newPlanner(engine *policy.Engine, auditLog *audit.AuditLog, runner toolRunner, killed func() bool) *planner {
	return &planner{
		engine: engine,
		audit:  auditLog,
		runner: runner,
		killed: killed,
		store:  map[string]plan.Document{},
	}
}

// withApprovals wires the out-of-band authoriser used for approve-disposition
// steps. Called only when the policy configures an approvals webhook; a plan step
// that hits an hold rule then blocks on the same authoriser a direct call would,
// so apply is never a way around dual control.
func (p *planner) withApprovals(approver enforce.Approver, sessionID string, timeout time.Duration) *planner {
	p.approver = approver
	p.sessionID = sessionID
	p.approvalTimeout = timeout
	return p
}

// Propose validates and adjudicates a submitted plan, stores it under its content
// hash, and returns the change manifest and plan id.
func (p *planner) Propose(ctx context.Context, rawPlan []byte) (windows.PlanProposal, error) {
	dec := json.NewDecoder(bytes.NewReader(rawPlan))
	dec.DisallowUnknownFields()
	var doc plan.Document
	if err := dec.Decode(&doc); err != nil {
		return windows.PlanProposal{}, fmt.Errorf("parse plan: %w", err)
	}
	if err := doc.Validate(); err != nil {
		return windows.PlanProposal{}, fmt.Errorf("invalid plan: %w", err)
	}
	for i, s := range doc.Steps {
		if s.Tool == "Plan" || s.Tool == "Apply" {
			return windows.PlanProposal{}, fmt.Errorf("%w: step %d", ErrPlanContainsPlanning, i)
		}
		if !p.runner.Has(s.Tool) {
			return windows.PlanProposal{}, fmt.Errorf("%w: step %d: %s", ErrToolNotServed, i, s.Tool)
		}
	}

	doc, err := doc.WithID()
	if err != nil {
		return windows.PlanProposal{}, fmt.Errorf("hash plan: %w", err)
	}

	pv := p.engine.EvaluatePlan(ctx, p.subjects(doc))

	p.mu.Lock()
	p.store[doc.PlanID] = doc
	p.mu.Unlock()

	// Compact record: the plan id, per-step tool and argument digest, and the
	// verdict. The full document (with argument values) is for the evidence bundle,
	// not the hashed, fsync'd chain.
	_, _ = p.audit.Append("plan.proposed", map[string]any{
		"plan_id":  doc.PlanID,
		"steps":    stepDigests(doc),
		"severity": pv.Severity.String(),
		"allowed":  pv.Allowed(),
	})

	manifest := doc.Render() + fmt.Sprintf("\nVerdict: %s (%s)\nApply with plan_id %s\n",
		pv.Severity, admitWord(pv.Allowed()), doc.PlanID)
	return windows.PlanProposal{
		PlanID:   doc.PlanID,
		Allowed:  pv.Allowed(),
		Severity: pv.Severity.String(),
		Manifest: manifest,
	}, nil
}

// Apply runs a stored plan by id: it re-checks posture, then executes the steps in
// order, stopping at the first that is refused or fails.
func (p *planner) Apply(ctx context.Context, planID string) (windows.PlanApplication, error) {
	p.mu.Lock()
	doc, ok := p.store[planID]
	p.mu.Unlock()
	if !ok {
		return windows.PlanApplication{}, fmt.Errorf("%w: %q", ErrUnknownPlan, planID)
	}

	// Posture may have changed since the plan was proposed. Re-adjudicate the whole
	// plan against live signals before starting; this does not spend rate-limit
	// budget (the per-step check below does, at execution time).
	if pv := p.engine.EvaluatePlan(ctx, p.subjects(doc)); !pv.Allowed() {
		_, _ = p.audit.Append("plan.refused", map[string]any{"plan_id": planID, "severity": pv.Severity.String()})
		return windows.PlanApplication{
			PlanID: planID,
			Report: fmt.Sprintf("refused: device posture no longer admits this plan (%s)", pv.Severity),
			Failed: len(doc.Steps),
		}, nil
	}

	// A plan-gated tool needs a person, not just a shape. require_plan refuses a
	// direct call and tells the model to submit a plan instead -- which the model
	// can do itself, so on its own it only forces the Plan/Apply shape and adds the
	// manifest and the audit trail. This is where the human enters: if any step is
	// plan-gated, the whole plan is put to the same authoriser a hold step uses,
	// with the operations it will run named, before any of it starts.
	if gated := p.gatedSteps(doc); len(gated) > 0 {
		if d, err := p.approvePlan(ctx, planID, doc, gated); err != nil || d != enforce.OutcomeApprove {
			return windows.PlanApplication{
				PlanID: planID,
				Report: planApprovalReport(d, err),
				Failed: len(doc.Steps),
			}, nil
		}
	}

	var b strings.Builder
	completed, failed, skipped := 0, 0, 0
	for i, s := range doc.Steps {
		if p.killed != nil && p.killed() {
			skipped = len(doc.Steps) - i
			fmt.Fprintf(&b, "  abandoned at step %d: containment tripped\n", i+1)
			break
		}
		if ctx.Err() != nil {
			skipped = len(doc.Steps) - i
			fmt.Fprintf(&b, "  abandoned at step %d: cancelled\n", i+1)
			break
		}

		// Each step is evaluated again at the moment it runs — apply is an extra
		// gate, never a bypass — and this evaluation, unlike the plan-level one, is
		// the real per-call decision that spends rate-limit budget.
		v := p.engine.Evaluate(ctx, p.engine.SubjectForTool("tools/call", s.Tool))
		rawArgs, _ := json.Marshal(s.Args)
		_, _ = p.audit.Append("plan.step", map[string]any{
			"plan_id": planID, "index": i, "tool": s.Tool,
			"args_sha256": argsDigest(s.Args), "verdict": v.Severity.String(),
		})

		if !v.Allowed() {
			failed++
			skipped = len(doc.Steps) - i - 1
			fmt.Fprintf(&b, "  %d. %s — REFUSED: %s\n", i+1, stepLabel(s), v.Reason())
			break
		}

		// An approve-disposition step suspends on the same authoriser a direct call
		// would. A plan is pre-authored, so this is the moment a human sees the exact
		// operation about to run; a denial or a timeout halts the plan, fail-closed.
		if v.Severity == policy.SeverityHold {
			if d := p.adjudicateStep(ctx, s, v); d.Outcome != enforce.OutcomeApprove {
				failed++
				skipped = len(doc.Steps) - i - 1
				fmt.Fprintf(&b, "  %d. %s — NOT APPROVED: %s\n", i+1, stepLabel(s), approvalDetail(d))
				break
			}
		}

		res, err := p.runner.Invoke(ctx, s.Tool, rawArgs)
		if err != nil || (res != nil && res.IsError) {
			failed++
			skipped = len(doc.Steps) - i - 1
			fmt.Fprintf(&b, "  %d. %s — FAILED: %s\n", i+1, stepLabel(s), resultDetail(res, err))
			break
		}
		completed++
		fmt.Fprintf(&b, "  %d. %s — ok\n", i+1, stepLabel(s))
	}

	_, _ = p.audit.Append("plan.applied", map[string]any{
		"plan_id": planID, "completed": completed, "failed": failed, "skipped": skipped,
	})
	report := fmt.Sprintf("Applied plan %s: %d completed, %d failed, %d skipped\n%s",
		shortID(planID), completed, failed, skipped, b.String())
	return windows.PlanApplication{
		PlanID: planID, Report: report,
		Completed: completed, Failed: failed, Skipped: skipped,
	}, nil
}

// adjudicateStep suspends one approve-disposition step on the out-of-band
// authoriser, recording the request and outcome in the audit chain exactly as a
// suspended direct call does. A missing approver fails closed.
func (p *planner) adjudicateStep(ctx context.Context, s plan.Step, v policy.Verdict) enforce.Decision {
	if p.approver == nil {
		return enforce.Decision{Outcome: enforce.OutcomeError, Detail: "no approver configured"}
	}
	failed := make([]string, 0, len(v.Failures))
	for _, f := range v.Failures {
		failed = append(failed, f.Signal)
	}
	timeout := p.approvalTimeout
	if timeout <= 0 {
		timeout = policy.DefaultApprovalTimeout
	}
	now := time.Now()
	req := enforce.ApprovalRequest{
		RequestID:     enforce.NewRequestID(),
		SessionID:     p.sessionID,
		Method:        "tools/call",
		Tool:          s.Tool,
		ArgsDigest:    argsDigest(s.Args),
		Rules:         v.Rules,
		FailedSignals: failed,
		Reason:        v.Reason(),
		RequestedAt:   now,
		ExpiresAt:     now.Add(timeout),
	}
	return enforce.Adjudicate(ctx, p.approver, p.audit, req)
}

// approvalDetail renders an approval decision for the apply report.
func approvalDetail(d enforce.Decision) string {
	switch d.Outcome {
	case enforce.OutcomeTimeout:
		return "no decision before the deadline"
	case enforce.OutcomeDeny:
		if d.Detail != "" {
			return "refused by a approver: " + d.Detail
		}
		return "refused by a approver"
	default:
		if d.Detail != "" {
			return "approval unavailable: " + d.Detail
		}
		return "approval unavailable"
	}
}

// StoredPlans returns every plan proposed this session, ordered by id, so the
// evidence bundle can carry the full approved documents (the compact audit chain
// records only their digests).
func (p *planner) StoredPlans() []plan.Document {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]plan.Document, 0, len(p.store))
	for _, d := range p.store {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PlanID < out[j].PlanID })
	return out
}

func (p *planner) subjects(doc plan.Document) []policy.Subject {
	subjects := make([]policy.Subject, len(doc.Steps))
	for i, s := range doc.Steps {
		subjects[i] = p.engine.SubjectForTool("tools/call", s.Tool)
	}
	return subjects
}

func stepDigests(doc plan.Document) []map[string]any {
	out := make([]map[string]any, len(doc.Steps))
	for i, s := range doc.Steps {
		out[i] = map[string]any{"index": i, "tool": s.Tool, "args_sha256": argsDigest(s.Args)}
	}
	return out
}

// argsDigest is the SHA-256 of the canonical JSON of a step's arguments.
// encoding/json sorts map keys, so the same arguments always digest the same —
// which is what lets the proposal record and the applied-step record be compared.
func argsDigest(args map[string]any) string {
	b, err := json.Marshal(args)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func stepLabel(s plan.Step) string {
	if s.Name != "" {
		return s.Name + " [" + s.Tool + "]"
	}
	return s.Tool
}

func admitWord(allowed bool) string {
	if allowed {
		return "admitted"
	}
	return "refused"
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func resultDetail(res *mcp.CallToolResult, err error) string {
	if err != nil {
		return err.Error()
	}
	if res == nil {
		return "no result"
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	if b.Len() == 0 {
		return "error result"
	}
	return b.String()
}

// gatedSteps returns the tools in doc that require_plan covers.
func (p *planner) gatedSteps(doc plan.Document) []string {
	var gated []string
	seen := map[string]bool{}
	for _, s := range doc.Steps {
		if seen[s.Tool] {
			continue
		}
		if p.engine.RequiresPlan(p.engine.SubjectForTool("tools/call", s.Tool)) {
			seen[s.Tool] = true
			gated = append(gated, s.Tool)
		}
	}
	return gated
}

// approvePlan puts the whole plan to the out-of-band authoriser.
//
// Fails closed in every direction, and deliberately so: a require_plan rule is an
// operator saying these tools need review, so no approver configured means there
// is nobody to review and the plan does not run. The alternative -- proceeding
// when the webhook is absent -- would make the strictest configuration the one
// that silently checks nothing.
//
// The request carries the tool names and a digest of the plan, never the raw
// arguments, matching what a hold step sends.
func (p *planner) approvePlan(
	ctx context.Context,
	planID string,
	doc plan.Document,
	gated []string,
) (enforce.Outcome, error) {
	if p.approver == nil {
		_, _ = p.audit.Append("plan.approval.unavailable", map[string]any{
			"plan_id": planID, "gated_tools": gated,
		})
		return enforce.OutcomeDeny, ErrPlanApprovalUnavailable
	}

	req := enforce.ApprovalRequest{
		RequestID:  enforce.NewRequestID(),
		SessionID:  p.sessionID,
		Method:     "plans/apply",
		Tool:       strings.Join(gated, ", "),
		ArgsDigest: planDigest(doc),
		Reason: fmt.Sprintf("plan %s applies %d step(s) including the plan-gated tool(s) %s",
			shortPlanID(planID), len(doc.Steps), strings.Join(gated, ", ")),
	}
	_, _ = p.audit.Append("approval.requested", map[string]any{
		"plan_id": planID, "request_id": req.RequestID, "gated_tools": gated,
	})

	ctx, cancel := context.WithTimeout(ctx, p.approvalTimeout)
	defer cancel()
	d := p.approver.Await(ctx, req)
	_, _ = p.audit.Append("approval.decided", map[string]any{
		"plan_id": planID, "request_id": req.RequestID,
		"outcome": string(d.Outcome), "approver": d.Approver,
	})
	return d.Outcome, nil
}

// planApprovalReport renders the refusal a caller sees.
func planApprovalReport(outcome enforce.Outcome, err error) string {
	if err != nil {
		return "refused: this plan contains tools that require review, and no approvals " +
			"webhook is configured to ask. Set approvals.webhook_url in the policy document."
	}
	return fmt.Sprintf("refused: the plan was not approved (%s)", outcome)
}

// planDigest is a digest of the plan's content for the approval request, so the
// authoriser can pin what they approved without seeing raw arguments.
func planDigest(doc plan.Document) string {
	raw, err := json.Marshal(doc.Steps)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// ErrPlanApprovalUnavailable reports a plan-gated apply with no authoriser.
var ErrPlanApprovalUnavailable = errors.New("no approvals webhook is configured")
