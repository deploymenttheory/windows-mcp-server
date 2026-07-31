package guardrails

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestKillSwitchFiresOnce(t *testing.T) {
	var n int32
	k := NewKillSwitch(func(string) { atomic.AddInt32(&n, 1) })
	k.Trip("a")
	k.Trip("b")
	if got := atomic.LoadInt32(&n); got != 1 {
		t.Errorf("onTrip called %d times, want 1", got)
	}
	if tripped, reason := k.Tripped(); !tripped || reason != "a" {
		t.Errorf("Tripped() = %v, %q; want true, \"a\"", tripped, reason)
	}
}

// callReq builds a tools/call request for the middleware.
func callReq(name, args string) *mcp.CallToolRequest {
	return &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: name, Arguments: json.RawMessage(args)}}
}

func runMiddleware(mw mcp.Middleware, req mcp.Request) (*mcp.CallToolResult, bool) {
	okResult := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}
	var reached bool
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		reached = true
		return okResult, nil
	}
	res, _ := mw(next)(context.Background(), "tools/call", req)
	ctr, _ := res.(*mcp.CallToolResult)
	return ctr, reached
}

func TestCircuitBreakerRateTrip(t *testing.T) {
	var tripped int32
	mw := ToolPolicyMiddleware(CircuitConfig{
		Enabled:   true,
		Threshold: 3,
		Window:    10 * time.Second,
		OnTrip:    func(string) { atomic.AddInt32(&tripped, 1) },
	})
	// First two sensitive calls pass; third trips and blocks.
	for i := 1; i <= 2; i++ {
		if res, reached := runMiddleware(mw, callReq("PowerShell", `{"command":"x"}`)); !reached || res.IsError {
			t.Fatalf("call %d should pass", i)
		}
	}
	res, reached := runMiddleware(mw, callReq("PowerShell", `{"command":"x"}`))
	if reached || !res.IsError {
		t.Error("3rd sensitive call should be blocked (not reach handler)")
	}
	if atomic.LoadInt32(&tripped) == 0 {
		t.Error("circuit breaker should have tripped the kill switch")
	}
}

func TestCircuitBreakerTripwire(t *testing.T) {
	var tripped int32
	mw := ToolPolicyMiddleware(CircuitConfig{
		Enabled: true,
		OnTrip:  func(string) { atomic.AddInt32(&tripped, 1) },
	})
	res, reached := runMiddleware(
		mw,
		callReq("PowerShell", `{"command":"Set-MpPreference -DisableRealtimeMonitoring $true"}`),
	)
	if reached || !res.IsError {
		t.Error("tripwire (disable Defender) should be blocked immediately")
	}
	if atomic.LoadInt32(&tripped) == 0 {
		t.Error("tripwire should fire the kill switch")
	}
}

// TestBlockedNonToolMethodsUseJSONRPCErrors pins the wire shape of a refusal on
// the methods that have no IsError envelope.
//
// The IsError-result convention belongs to tools/call. resources/read must return
// a ReadResourceResult and subscriptions/listen a SubscriptionsListenResult, so
// answering either with a CallToolResult puts a tool-result envelope on the wire
// where the schema requires something else. That is a conformance failure the
// 2026-07-28 wire-schema validation catches, and a client could not interpret it.
func TestBlockedNonToolMethodsUseJSONRPCErrors(t *testing.T) {
	cases := []struct {
		method  string
		params  mcp.Params
		subject string
	}{
		{"resources/read", &mcp.ReadResourceParams{URI: "windows://desktop/snapshot"}, "resource read"},
		{
			"subscriptions/listen",
			&mcp.SubscriptionsListenParams{Notifications: &mcp.NotificationSubscriptions{ToolsListChanged: true}},
			"subscription stream",
		},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			mw := ToolPolicyMiddleware(CircuitConfig{Enabled: true, Threshold: 2, Window: 10 * time.Second})
			next := func(context.Context, string, mcp.Request) (mcp.Result, error) {
				return &mcp.CallToolResult{}, nil
			}
			handler := mw(next)
			req := &mcp.ServerRequest[mcp.Params]{Params: tc.params}

			// First call is under the threshold and proceeds.
			if _, err := handler(context.Background(), tc.method, req); err != nil {
				t.Fatalf("first %s must pass: %v", tc.subject, err)
			}
			res, err := handler(context.Background(), tc.method, req)
			if err == nil {
				t.Fatalf("a blocked %s must fail the request, not return a result (%T)", tc.subject, res)
			}
			if res != nil {
				t.Errorf("a blocked %s must return a nil result, got %T", tc.subject, res)
			}
			var wire *jsonrpc.Error
			if !errors.As(err, &wire) {
				t.Fatalf("want a JSON-RPC wire error, got %T: %v", err, err)
			}
			if wire.Code != jsonrpc.CodeInvalidRequest {
				t.Errorf("code = %d, want %d (InvalidRequest); -32020..-32099 is reserved for the spec",
					wire.Code, jsonrpc.CodeInvalidRequest)
			}
		})
	}
}

// TestSubscriptionsListenSharesTheBreakerWindow guards the same evasion the
// resources/read arm closes: an agent must not be able to stay under the limit by
// moving from tool calls to subscription streams.
func TestSubscriptionsListenSharesTheBreakerWindow(t *testing.T) {
	mw := ToolPolicyMiddleware(CircuitConfig{Enabled: true, Threshold: 2, Window: 10 * time.Second})
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) { return &mcp.CallToolResult{}, nil }

	// One sensitive tool call, then a listen: the listen is the second hit in the
	// shared window and must be refused.
	if _, reached := runMiddleware(mw, callReq("PowerShell", `{"command":"x"}`)); !reached {
		t.Fatal("first sensitive call should pass")
	}
	listen := &mcp.ServerRequest[mcp.Params]{Params: &mcp.SubscriptionsListenParams{}}
	if _, err := mw(next)(context.Background(), "subscriptions/listen", listen); err == nil {
		t.Error("subscriptions/listen must count against the same window as tools/call")
	}
}

// TestDiscoverIsNotRateLimited pins the deliberate exception. server/discover
// replaced the initialize handshake and a client may probe it before every
// request under the stateless protocol, so rate-limiting it would break
// conformant clients rather than contain a hostile one.
func TestDiscoverIsNotRateLimited(t *testing.T) {
	mw := ToolPolicyMiddleware(CircuitConfig{Enabled: true, Threshold: 2, Window: 10 * time.Second})
	var reached int
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		reached++
		return &mcp.DiscoverResult{}, nil
	}
	req := &mcp.ServerRequest[mcp.Params]{Params: &mcp.DiscoverParams{}}
	for i := 0; i < 5; i++ {
		if _, err := mw(next)(context.Background(), "server/discover", req); err != nil {
			t.Fatalf("discover %d must not be blocked: %v", i, err)
		}
	}
	if reached != 5 {
		t.Errorf("every discover must reach the handler, got %d of 5", reached)
	}
}

func TestCircuitBreakerIgnoresReadOnly(t *testing.T) {
	mw := ToolPolicyMiddleware(CircuitConfig{Enabled: true, Threshold: 2})
	for i := 0; i < 5; i++ {
		if _, reached := runMiddleware(mw, callReq("Snapshot", `{}`)); !reached {
			t.Fatal("non-sensitive tool should never be blocked")
		}
	}
}

func TestDecisionJSONRoundTrips(t *testing.T) {
	d := Decision{
		Device:  DeviceIdentity{Hostname: "H"},
		Mode:    "enforce",
		Admit:   false,
		Reasons: []string{"x"},
		Results: []Result{{ID: "run-context", Status: Pass}},
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var back Decision
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Admit || back.Mode != "enforce" || len(back.Results) != 1 {
		t.Errorf("round-trip mismatch: %+v", back)
	}
}
