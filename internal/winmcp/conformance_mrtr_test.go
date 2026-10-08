//go:build windows && (amd64 || arm64) && conformance

package winmcp

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestMRTRThroughTheRealChain drives one SEP-2322 fixture through the host's
// full chain — inject-deps, cache hints, recover, audit, rug-pull, policy —
// with multi-round-trip disabled on the client so each round is a separate
// request, the way the stateless HTTP suite sends them. The fixtures' own
// behaviour is pinned in mcp-server-core; what is pinned here is that this
// server's chain lets the suspended request through intact.
func TestMRTRThroughTheRealChain(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := buildConformanceServer(ctx, Config{Toolsets: []string{"all"}}, true, logger)
	if err != nil {
		t.Fatal(err)
	}
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ss.Close() }()
	client := mcp.NewClient(&mcp.Implementation{Name: "mrtr-test", Version: "test"},
		&mcp.ClientOptions{MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true}})
	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "test_input_required_result_elicitation"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.NeedsInput() {
		t.Fatal("round 1 should be input_required")
	}
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "test_input_required_result_elicitation",
		InputResponses: mcp.InputResponseMap{
			"user_name": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"name": "Alice"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.NeedsInput() {
		t.Fatal("round 2 should complete")
	}
	var text string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok && !strings.HasPrefix(tc.Text, "device policy warning:") {
			text = tc.Text
			break
		}
	}
	if text != "Hello, Alice!" {
		t.Errorf("completion text = %q, want %q", text, "Hello, Alice!")
	}
}
