package guardrails

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestKillToolRoutesToSuppliedStop pins the indirection that lets the server layer
// decide what "Kill" means: the tool never reaches for the kill switch itself, so
// an unarmed operator gets a graceful stop instead of the containment ladder.
func TestKillToolRoutesToSuppliedStop(t *testing.T) {
	var got string
	tool, handler := KillTool(func(reason string) { got = reason })

	if tool.Name != "Kill" {
		t.Errorf("tool name = %q, want Kill", tool.Name)
	}
	if tool.Annotations == nil || tool.Annotations.DestructiveHint == nil || !*tool.Annotations.DestructiveHint {
		t.Error("Kill must carry a destructive hint")
	}

	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{
		Name:      "Kill",
		Arguments: json.RawMessage(`{"reason":"journey complete"}`),
	}}
	res, err := handler(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || len(res.Content) == 0 {
		t.Fatal("Kill must return a result")
	}
	if !strings.Contains(got, "journey complete") {
		t.Errorf("stop reason = %q, want the caller's reason", got)
	}
}

// TestKillToolWithoutReasonStillStops covers the no-arguments call.
func TestKillToolWithoutReasonStillStops(t *testing.T) {
	var called bool
	_, handler := KillTool(func(string) { called = true })

	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "Kill"}}
	if _, err := handler(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("Kill with no reason must still stop the session")
	}
}
