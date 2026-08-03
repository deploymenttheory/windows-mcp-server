// Package enforce is the enforcement point: the MCP middleware that asks the
// engine about a request and then acts on the answer.
//
// It is deliberately separate from package policy. The engine decides; this
// package is the only thing that turns a decision into a refusal, a warning
// attached to a result, or a kill. Everything MCP-shaped about enforcement —
// which methods are decidable, what a refusal looks like on the wire for each of
// them — lives here rather than leaking into the decision logic.
package enforce

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"sort"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy"
)

// EnforcerDeps wires the enforcement point to the rest of the server.
type EnforcerDeps struct {
	// Audit records every verdict. Required in practice: a decision nobody can
	// see is not a control.
	Audit *audit.AuditLog
	// Kill fires the kill switch. The caller supplies it already gated on the
	// policy's trigger settings, so a trigger the operator left off is
	// report-only rather than absent — detection is never conditional on
	// containment.
	Kill func(reason string)
	// RecordDecision, if set, is called for every verdict with the subject, the
	// effective severity and the mode — the telemetry hook. Optional: nil when no
	// collector is configured.
	RecordDecision func(subject, severity, mode string)
	// Approver adjudicates hold verdicts out of band. Nil when no approvals
	// webhook is configured; a policy that uses on_fail hold without one is
	// refused at load, so a nil Approver here means no hold rule can fire. If one
	// somehow does with no approver, the call is refused — dual control fails closed.
	Approver Approver
	// SessionID labels approval requests so a approver can correlate them; the same
	// per-session stamp the audit chain and evidence bundle use.
	SessionID string
	// ApprovalTimeout is how long a suspended call may wait. Zero lets the client
	// apply its default.
	ApprovalTimeout time.Duration
	Logger          *slog.Logger
}

// Methods the engine decides on. Everything else passes through untouched:
// tools/list and server/discover carry no action, and gating discovery would
// break a client's ability to see why it is being refused.
const (
	methodCallTool     = "tools/call"
	methodReadResource = "resources/read"
	methodGetPrompt    = "prompts/get"
)

// Middleware returns MCP receiving middleware that decides every actionable
// request before it reaches its handler.
//
// It belongs innermost in the chain, so nothing can route around it and so the
// audit and rug-pull layers still observe requests it refuses.
func Middleware(engine *policy.Engine, deps EnforcerDeps) mcp.Middleware {
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			subj, decidable := subjectFor(engine, method, req)
			if !decidable {
				return next(ctx, method, req)
			}

			// A tool gated by require_plan may only run inside a approved plan. Plan
			// steps are executed by the planner and never reach this middleware, so a
			// matching call here is by definition a direct call — refuse it before it
			// runs, and record that the plan requirement fired.
			if method == methodCallTool && engine.RequiresPlan(subj) {
				if deps.Audit != nil {
					_, _ = deps.Audit.Append("plan.required", map[string]any{"subject": subj.String()})
				}
				logger.Warn("plan.required", "subject", subj.String())
				return refusePlanRequired(subj)
			}

			v := engine.Evaluate(ctx, subj)
			record(deps, logger, v)

			switch {
			case v.Severity >= policy.SeverityKill:
				// Audited above, before any containment.
				if deps.Kill != nil {
					deps.Kill("policy: " + v.Subject + ": " + v.Reason())
				}
				return refuse(method, v)
			case v.Severity >= policy.SeverityDeny:
				return refuse(method, v)
			case v.Severity == policy.SeverityHold:
				d := awaitApproval(ctx, deps, logger, method, req, v)
				if d.Outcome != OutcomeApprove {
					return refuseApproval(method, v, d)
				}
				return next(ctx, method, req)
			case v.Severity == policy.SeverityWarn:
				res, err := next(ctx, method, req)
				return attachWarning(res, v), err
			default:
				return next(ctx, method, req)
			}
		}
	}
}

// record writes the verdict to the audit chain and the log.
//
// This happens for every decidable request, in every mode, including allows.
// An audit trail that only recorded refusals could not answer the question that
// actually gets asked after an incident: what did this session do while the
// device looked healthy?
func record(deps EnforcerDeps, logger *slog.Logger, v policy.Verdict) {
	fields := map[string]any{
		"subject":  v.Subject,
		"verdict":  v.Severity.String(),
		"intended": v.Intended.String(),
		"mode":     string(v.Mode),
	}
	if len(v.Rules) > 0 {
		fields["rules"] = v.Rules
	}
	if len(v.Failures) > 0 {
		failed := make([]string, 0, len(v.Failures))
		for _, f := range v.Failures {
			failed = append(failed, f.Signal)
		}
		fields["failed_signals"] = failed
		fields["reason"] = v.Reason()
	}
	if deps.Audit != nil {
		_, _ = deps.Audit.Append("policy.decision", fields)
	}
	if deps.RecordDecision != nil {
		deps.RecordDecision(v.Subject, v.Severity.String(), string(v.Mode))
	}

	switch {
	case v.Severity >= policy.SeverityDeny:
		logger.Error("policy.decision", "subject", v.Subject, "verdict", v.Severity.String(),
			"reason", v.Reason())
	case len(v.Failures) > 0:
		// Includes the audit-mode case, where Intended outranks Severity. That
		// line is the one an operator reads to decide whether enforcing is safe.
		logger.Warn("policy.decision", "subject", v.Subject, "verdict", v.Severity.String(),
			"would_be", v.Intended.String(), "reason", v.Reason())
	default:
		logger.Debug("policy.decision", "subject", v.Subject, "verdict", v.Severity.String())
	}
}

// refuse renders a denial in the shape the method requires.
//
// tools/call gets an IsError result with a nil Go error, which is this project's
// convention and lets the model read the reason and adapt. resources/read and
// prompts/get have no IsError envelope — their results are ReadResourceResult
// and GetPromptResult — so a refusal there must be a JSON-RPC error. Returning a
// CallToolResult would put the wrong shape on the wire.
func refuse(method string, v policy.Verdict) (mcp.Result, error) {
	msg := "blocked by device policy: " + v.Reason()
	if method == methodCallTool {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, nil
	}
	// InvalidRequest rather than an MCP-specific code: protocol revision
	// 2026-07-28 reserves -32020..-32099 for the specification, so a
	// server-policy refusal has no business minting a code in that range.
	return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidRequest, Message: msg}
}

// refusePlanRequired denies a direct call to a plan-gated tool. It is a tools/call
// refusal only — require_plan selects tools — so it always takes the IsError
// shape, letting the model read the reason and re-submit the call through a plan.
func refusePlanRequired(subj policy.Subject) (mcp.Result, error) {
	msg := "policy requires this tool to run inside a approved plan (" + subj.String() +
		"): submit it with Plan, then Apply the returned plan_id"
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, nil
}

// awaitApproval suspends a call on the out-of-band authoriser and reports the
// decision. A missing approver fails closed: the switch already routed here on an
// hold verdict, and a verdict nobody can adjudicate must not slip through as an
// allow.
func awaitApproval(
	ctx context.Context,
	deps EnforcerDeps,
	logger *slog.Logger,
	method string,
	req mcp.Request,
	v policy.Verdict,
) Decision {
	if deps.Approver == nil {
		logger.Error("hold verdict with no approver configured; refusing", "subject", v.Subject)
		return Decision{Outcome: OutcomeError, Detail: "no approver configured"}
	}
	logger.Info("call suspended for approval", "subject", v.Subject, "reason", v.Reason())
	areq := approvalRequestFor(deps, method, req, v)
	return Adjudicate(ctx, deps.Approver, deps.Audit, areq)
}

// approvalRequestFor builds the ApprovalRequest for a suspended call from its
// verdict and parameters. Only a digest of the arguments travels, never the
// arguments — the authoriser decides on the call's identity, as the audit chain does.
func approvalRequestFor(deps EnforcerDeps, method string, req mcp.Request, v policy.Verdict) ApprovalRequest {
	now := time.Now()
	timeout := deps.ApprovalTimeout
	if timeout <= 0 {
		timeout = policy.DefaultApprovalTimeout
	}
	failed := make([]string, 0, len(v.Failures))
	for _, f := range v.Failures {
		failed = append(failed, f.Signal)
	}
	return ApprovalRequest{
		RequestID:     randomID(),
		SessionID:     deps.SessionID,
		Method:        method,
		Tool:          toolName(req),
		ArgsDigest:    digestParams(req),
		Rules:         v.Rules,
		FailedSignals: failed,
		Reason:        v.Reason(),
		RequestedAt:   now,
		ExpiresAt:     now.Add(timeout),
	}
}

// toolName extracts the tool (or prompt) name a request targets, for the approval
// record. resources/read carries a URI rather than a name.
func toolName(req mcp.Request) string {
	switch p := req.GetParams().(type) {
	case *mcp.CallToolParamsRaw:
		return p.Name
	case *mcp.GetPromptParams:
		return p.Name
	case *mcp.ReadResourceParams:
		return p.URI
	default:
		return ""
	}
}

// digestParams renders a stable SHA-256 digest of a request's arguments, matching
// the audit chain's discipline of recording a digest and never the raw values.
func digestParams(req mcp.Request) string {
	var raw []byte
	switch p := req.GetParams().(type) {
	case *mcp.CallToolParamsRaw:
		raw = p.Arguments
	case *mcp.ReadResourceParams:
		raw = []byte(p.URI)
	case *mcp.GetPromptParams:
		raw = promptArgBytes(p.Arguments)
	default:
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// promptArgBytes serialises prompt arguments deterministically so equal arguments
// digest equally.
func promptArgBytes(args map[string]string) []byte {
	if len(args) == 0 {
		return nil
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b []byte
	for _, k := range keys {
		b = append(b, k...)
		b = append(b, '=')
		b = append(b, args[k]...)
		b = append(b, '\n')
	}
	return b
}

// refuseApproval renders a denial that names why approval did not carry, in the
// shape the method requires (see refuse).
func refuseApproval(method string, v policy.Verdict, d Decision) (mcp.Result, error) {
	var msg string
	switch d.Outcome {
	case OutcomeTimeout:
		msg = "blocked: no approval within the time limit for " + v.Subject
	case OutcomeDeny:
		msg = "blocked: a approver refused " + v.Subject
		if d.Detail != "" {
			msg += " (" + d.Detail + ")"
		}
	default:
		msg = "blocked: approval could not be obtained for " + v.Subject
		if d.Detail != "" {
			msg += " (" + d.Detail + ")"
		}
	}
	if method == methodCallTool {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, nil
	}
	return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidRequest, Message: msg}
}

// attachWarning surfaces an amber verdict to the caller.
//
// Amber means the call proceeded but something about the device is wrong. The
// model is the only party that can react in the moment, so the warning rides
// back with the result rather than living only in the operator's log. Only
// tool results carry it: the other methods have no free-text channel, and their
// warnings are in the audit chain.
func attachWarning(res mcp.Result, v policy.Verdict) mcp.Result {
	ctr, ok := res.(*mcp.CallToolResult)
	if !ok || ctr == nil {
		return res
	}
	warning := &mcp.TextContent{Text: "device policy warning: " + v.Reason()}
	ctr.Content = append([]mcp.Content{warning}, ctr.Content...)
	return ctr
}

// subjectFor resolves a request to the thing being decided about, and reports
// whether this method is subject to policy at all.
func subjectFor(engine *policy.Engine, method string, req mcp.Request) (policy.Subject, bool) {
	switch method {
	case methodCallTool:
		p, ok := req.GetParams().(*mcp.CallToolParamsRaw)
		if !ok {
			return policy.Subject{}, false
		}
		return engine.SubjectForTool(method, p.Name), true

	case methodReadResource:
		p, ok := req.GetParams().(*mcp.ReadResourceParams)
		if !ok {
			return policy.Subject{}, false
		}
		return dataEgressSubject(method, p.URI), true

	case methodGetPrompt:
		p, ok := req.GetParams().(*mcp.GetPromptParams)
		if !ok {
			return policy.Subject{}, false
		}
		return dataEgressSubject(method, p.Name), true

	default:
		return policy.Subject{}, false
	}
}

// dataEgressSubject builds the subject for a resource read or a prompt fetch.
//
// Both return server-held state to the caller, so they are read-only data-egress
// paths and are marked as such: a rule written as `annotation: read-only`, or as
// `toolset: "*"`, covers them. That is deliberate — a resource exposing the same
// desktop state as a tool must not be a way around the rule covering that tool.
// They carry no toolset, so a rule naming a specific toolset or tool does not
// reach them; expressing "this resource specifically" is not something the
// schema supports today, and pretending otherwise would be worse than the gap.
func dataEgressSubject(method, name string) policy.Subject {
	return policy.Subject{
		Scope:  policy.ScopeCall,
		Method: method,
		Facts:  policy.ToolFacts{Name: name, ReadOnly: true},
	}
}
