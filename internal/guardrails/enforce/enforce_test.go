package enforce

import (
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/signals"

	"context"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// enforceHarness wires an engine, an audit sink and a kill counter around the
// middleware, and records whether the handler was reached.
type enforceHarness struct {
	engine  *policy.Engine
	sink    *memSink
	kills   atomic.Int32
	reached atomic.Int32
	handler mcp.MethodHandler
}

func newEnforceHarness(t *testing.T, policyJSON string, outcomes map[string]signals.Status) *enforceHarness {
	t.Helper()
	e := newTestEngine(t, policyJSON, outcomes)
	h := &enforceHarness{engine: e, sink: &memSink{}}
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		h.reached.Add(1)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
	}
	h.handler = Middleware(e, EnforcerDeps{
		Audit: audit.NewAuditLog(h.sink),
		Kill:  func(string) { h.kills.Add(1) },
	})(next)
	return h
}

func (h *enforceHarness) call(method string, params mcp.Params) (mcp.Result, error) {
	req := &mcp.ServerRequest[mcp.Params]{Params: params}
	return h.handler(context.Background(), method, req)
}

func (h *enforceHarness) events() []string {
	out := make([]string, 0, len(h.sink.entries))
	for _, e := range h.sink.entries {
		out = append(out, e.Event)
	}
	return out
}

const denyPolicy = `{
  "version": 1, "mode": "enforce",
  "signals": { "bitlocker": { "ttl": "0s" } },
  "rules": [ { "name": "everything", "match": { "toolset": "*" }, "require": ["bitlocker"], "on_fail": "deny" } ]
}`

// TestDenyOnToolCallIsAnIsErrorResult pins this project's convention: an expected,
// user-facing refusal is an IsError result with a nil Go error, so the model can
// read the reason and adapt rather than seeing a transport failure.
func TestDenyOnToolCallIsAnIsErrorResult(t *testing.T) {
	h := newEnforceHarness(t, denyPolicy, map[string]signals.Status{"bitlocker": signals.Fail})

	res, err := h.call("tools/call", &mcp.CallToolParamsRaw{Name: "PowerShell"})
	if err != nil {
		t.Fatalf("a policy refusal must not be a Go error: %v", err)
	}
	ctr, ok := res.(*mcp.CallToolResult)
	if !ok {
		t.Fatalf("result type = %T, want *mcp.CallToolResult", res)
	}
	if !ctr.IsError {
		t.Error("a refused tool call must be marked IsError")
	}
	if h.reached.Load() != 0 {
		t.Error("a denied call must not reach the handler")
	}
	text := ctr.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, "bitlocker") {
		t.Errorf("the refusal must name the failing signal, got %q", text)
	}
}

// TestRequirePlanRefusesDirectCall pins the preventive tier: a direct call to a
// plan-gated tool is refused (an IsError result, since it is tools/call) and
// audited plan.required, while an ungated tool passes. A plan step never reaches
// this middleware, so gating here does not touch execution via Apply.
func TestRequirePlanRefusesDirectCall(t *testing.T) {
	const gated = `{
	  "version": 1, "mode": "enforce", "signals": {},
	  "require_plan": [ { "annotation": "destructive" } ]
	}`
	h := newEnforceHarness(t, gated, map[string]signals.Status{})

	// PowerShell is destructive → gated → refused before the handler.
	res, err := h.call("tools/call", &mcp.CallToolParamsRaw{Name: "PowerShell"})
	if err != nil {
		t.Fatalf("a plan-required refusal must not be a Go error: %v", err)
	}
	ctr, ok := res.(*mcp.CallToolResult)
	if !ok || !ctr.IsError {
		t.Fatalf("a gated direct call should be an IsError result, got %T %+v", res, res)
	}
	if text := ctr.Content[0].(*mcp.TextContent).Text; !strings.Contains(text, "approved plan") {
		t.Errorf("the refusal should tell the model to use a plan, got %q", text)
	}
	if h.reached.Load() != 0 {
		t.Error("a gated call must not reach the handler")
	}
	if !slices.Contains(h.events(), "plan.required") {
		t.Errorf("a gated call should be audited plan.required, got %v", h.events())
	}

	// Snapshot is read-only → not gated → passes through to the handler.
	res2, _ := h.call("tools/call", &mcp.CallToolParamsRaw{Name: "Snapshot"})
	if ctr2, ok := res2.(*mcp.CallToolResult); !ok || ctr2.IsError {
		t.Errorf("an ungated tool should pass, got %T %+v", res2, res2)
	}
	if h.reached.Load() != 1 {
		t.Error("the ungated call should reach the handler")
	}
}

// TestDenyOnResourceReadIsAJSONRPCError guards the wire shape. resources/read
// must return a ReadResourceResult; answering with a CallToolResult would put a
// tool-result envelope where the schema requires something else, which the MCP
// conformance suite's wire validation rejects and a client cannot interpret.
func TestDenyOnResourceReadIsAJSONRPCError(t *testing.T) {
	h := newEnforceHarness(t, denyPolicy, map[string]signals.Status{"bitlocker": signals.Fail})

	res, err := h.call("resources/read", &mcp.ReadResourceParams{URI: "windows://desktop/snapshot"})
	if err == nil {
		t.Fatalf("a refused resource read must fail the request, got result %T", res)
	}
	if res != nil {
		t.Errorf("a refused resource read must return a nil result, got %T", res)
	}
	var wire *jsonrpc.Error
	if !errors.As(err, &wire) {
		t.Fatalf("want a JSON-RPC wire error, got %T: %v", err, err)
	}
	if wire.Code != jsonrpc.CodeInvalidRequest {
		t.Errorf("code = %d, want %d; -32020..-32099 is reserved for the spec",
			wire.Code, jsonrpc.CodeInvalidRequest)
	}
	if h.reached.Load() != 0 {
		t.Error("a denied resource read must not reach the handler")
	}
}

// TestPromptGetIsCoveredToo: prompts steer the model, so a rule covering tools
// must not leave prompts/get as an unpoliced path.
func TestPromptGetIsCoveredToo(t *testing.T) {
	h := newEnforceHarness(t, denyPolicy, map[string]signals.Status{"bitlocker": signals.Fail})
	if _, err := h.call("prompts/get", &mcp.GetPromptParams{Name: "rpa-journey"}); err == nil {
		t.Error("prompts/get must be subject to policy")
	}
}

// TestKillVerdictTripsOnceAndStillRefuses covers the very-red path.
func TestKillVerdictTripsOnceAndStillRefuses(t *testing.T) {
	killPolicy := `{
	  "version": 1, "mode": "enforce",
	  "signals": { "bitlocker": { "ttl": "0s" } },
	  "rules": [ { "name": "out-of-bounds", "match": { "toolset": "*" }, "require": ["bitlocker"], "on_fail": "kill" } ]
	}`
	h := newEnforceHarness(t, killPolicy, map[string]signals.Status{"bitlocker": signals.Fail})

	res, err := h.call("tools/call", &mcp.CallToolParamsRaw{Name: "PowerShell"})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if ctr, ok := res.(*mcp.CallToolResult); !ok || !ctr.IsError {
		t.Error("a kill verdict must also refuse the call that triggered it")
	}
	if got := h.kills.Load(); got != 1 {
		t.Errorf("kill fired %d times, want 1", got)
	}
	if h.reached.Load() != 0 {
		t.Error("a killed call must not reach the handler")
	}
	// The audit entry must exist and must precede containment; the trip is
	// recorded by the executor, this entry is the decision that caused it.
	if events := h.events(); len(events) == 0 || events[0] != "policy.decision" {
		t.Errorf("the decision must be audited before containment, got %v", events)
	}
}

// TestWarnProceedsAndTellsTheCaller is the amber path: the call runs, but the
// model is told the device is not healthy so it can act on it in the moment.
func TestWarnProceedsAndTellsTheCaller(t *testing.T) {
	warnPolicy := `{
	  "version": 1, "mode": "enforce",
	  "signals": { "bitlocker": { "ttl": "0s" } },
	  "rules": [ { "name": "soft", "match": { "toolset": "*" }, "require": ["bitlocker"], "on_fail": "warn" } ]
	}`
	h := newEnforceHarness(t, warnPolicy, map[string]signals.Status{"bitlocker": signals.Fail})

	res, err := h.call("tools/call", &mcp.CallToolParamsRaw{Name: "Snapshot"})
	if err != nil {
		t.Fatal(err)
	}
	if h.reached.Load() != 1 {
		t.Fatal("a warn verdict must let the call through")
	}
	ctr := res.(*mcp.CallToolResult)
	if ctr.IsError {
		t.Error("a warning must not mark the result as an error")
	}
	if len(ctr.Content) < 2 {
		t.Fatalf("want the warning prepended to the real content, got %d blocks", len(ctr.Content))
	}
	if text := ctr.Content[0].(*mcp.TextContent).Text; !strings.Contains(text, "bitlocker") {
		t.Errorf("warning text = %q, want it to name the failing signal", text)
	}
	if text := ctr.Content[1].(*mcp.TextContent).Text; text != "ok" {
		t.Errorf("the handler's own content must be preserved, got %q", text)
	}
}

// TestAuditRecordsEveryDecisionIncludingAllows. An audit trail that only held
// refusals could not answer the question asked after an incident: what did this
// session do while the device looked healthy?
func TestAuditRecordsEveryDecisionIncludingAllows(t *testing.T) {
	h := newEnforceHarness(t, denyPolicy, map[string]signals.Status{"bitlocker": signals.Pass})

	if _, err := h.call("tools/call", &mcp.CallToolParamsRaw{Name: "Snapshot"}); err != nil {
		t.Fatal(err)
	}
	if h.reached.Load() != 1 {
		t.Fatal("a passing device must let the call through")
	}
	if events := h.events(); len(events) != 1 || events[0] != "policy.decision" {
		t.Errorf("an allowed call must still be audited, got %v", events)
	}
	if err := audit.VerifyChain(h.sink.entries); err != nil {
		t.Errorf("audit chain must stay verifiable: %v", err)
	}
}

// TestAuditModeRecordsWhatEnforcingWouldHaveDone is what makes audit mode worth
// running: the operator needs to see the refusals a policy would cause before
// switching it on.
func TestAuditModeRecordsWhatEnforcingWouldHaveDone(t *testing.T) {
	auditPolicy := `{
	  "version": 1, "mode": "audit",
	  "signals": { "bitlocker": { "ttl": "0s" } },
	  "rules": [ { "name": "everything", "match": { "toolset": "*" }, "require": ["bitlocker"], "on_fail": "kill" } ]
	}`
	h := newEnforceHarness(t, auditPolicy, map[string]signals.Status{"bitlocker": signals.Fail})

	if _, err := h.call("tools/call", &mcp.CallToolParamsRaw{Name: "PowerShell"}); err != nil {
		t.Fatal(err)
	}
	if h.reached.Load() != 1 {
		t.Error("audit mode must not refuse")
	}
	if h.kills.Load() != 0 {
		t.Error("audit mode must never contain")
	}
	payload := string(h.sink.entries[0].Payload)
	if !strings.Contains(payload, `"intended":"kill"`) {
		t.Errorf("the audit record must say what enforcing would have done: %s", payload)
	}
	if !strings.Contains(payload, `"verdict":"warn"`) {
		t.Errorf("the audit record must say what actually happened: %s", payload)
	}
}

// TestUndecidableMethodsPassThrough: gating discovery would stop a client seeing
// the manifest, and with it any explanation of why calls are being refused.
func TestUndecidableMethodsPassThrough(t *testing.T) {
	h := newEnforceHarness(t, denyPolicy, map[string]signals.Status{"bitlocker": signals.Fail})

	for _, method := range []string{"tools/list", "server/discover", "resources/list", "prompts/list"} {
		if _, err := h.call(method, &mcp.ListToolsParams{}); err != nil {
			t.Errorf("%s must not be gated: %v", method, err)
		}
	}
	if got := h.reached.Load(); got != 4 {
		t.Errorf("all four discovery calls should reach the handler, got %d", got)
	}
	if len(h.sink.entries) != 0 {
		t.Errorf("undecidable methods should not produce policy decisions, got %v", h.events())
	}
}
