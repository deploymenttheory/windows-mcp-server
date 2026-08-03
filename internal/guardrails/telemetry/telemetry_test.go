package telemetry

import (
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestParseHeaders(t *testing.T) {
	got := ParseHeaders("Authorization=Bearer abc, X-Tenant=acme")
	if got["Authorization"] != "Bearer abc" || got["X-Tenant"] != "acme" {
		t.Errorf("headers = %v", got)
	}
	if v := ParseHeaders("k=a=b"); v["k"] != "a=b" {
		t.Errorf("a value may contain '=', got %q", v["k"])
	}
	if ParseHeaders("") != nil || ParseHeaders("   ") != nil {
		t.Error("empty input should yield nil")
	}
}

// TestMiddlewareAndRecordAreNonBlocking constructs telemetry against a collector
// that is not listening and drives the middleware and the decision counter. Spans
// and metrics are buffered and exported in the background, so nothing here should
// block or fail; Shutdown is given a short deadline so a dead collector cannot
// hang the test.
func TestMiddlewareAndRecordAreNonBlocking(t *testing.T) {
	tel, err := New(context.Background(), Config{Endpoint: "localhost:4318", ServiceName: "test", Version: "1"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	reached := 0
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		reached++
		return &mcp.CallToolResult{}, nil
	}
	mw := tel.Middleware()
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "Snapshot"}}

	if _, err := mw(next)(context.Background(), "tools/call", req); err != nil {
		t.Fatalf("traced call: %v", err)
	}
	// A non-decidable method passes through untraced but still reaches next.
	if _, err := mw(next)(context.Background(), "tools/list", req); err != nil {
		t.Fatalf("untraced call: %v", err)
	}
	if reached != 2 {
		t.Errorf("middleware must always call next, reached=%d", reached)
	}

	tel.RecordDecision("tools/call Snapshot", "deny", "enforce")

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	tel.Shutdown(ctx)
}

func TestIsErrorResult(t *testing.T) {
	if !isErrorResult(&mcp.CallToolResult{IsError: true}) {
		t.Error("an IsError result should be detected")
	}
	if isErrorResult(&mcp.CallToolResult{}) {
		t.Error("a normal result is not an error")
	}
	if isErrorResult(nil) {
		t.Error("nil is not an error result")
	}
}
