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
	"log/slog"

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
	Kill   func(reason string)
	Logger *slog.Logger
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
