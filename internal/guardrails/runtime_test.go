package guardrails

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

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
	res, reached := runMiddleware(mw, callReq("PowerShell", `{"command":"Set-MpPreference -DisableRealtimeMonitoring $true"}`))
	if reached || !res.IsError {
		t.Error("tripwire (disable Defender) should be blocked immediately")
	}
	if atomic.LoadInt32(&tripped) == 0 {
		t.Error("tripwire should fire the kill switch")
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
