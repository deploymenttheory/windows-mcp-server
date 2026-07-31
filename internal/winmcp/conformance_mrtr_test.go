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

// These tests drive the SEP-2322 fixtures through the same construction the
// conformance host serves — buildConformanceServer with fixtures on, so the
// full inject-deps/audit/rug-pull/policy chain sits between the client and the
// handler. MultiRoundTrip is disabled on the client so each round is a real,
// separate request, the way the stateless HTTP suite sends them.

func connectFixturesClient(t *testing.T, ctx context.Context, opts *mcp.ClientOptions) *mcp.ClientSession {
	t.Helper()
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
	t.Cleanup(func() { _ = ss.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "mrtr-test", Version: "test"}, opts)
	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func manualRoundTripOptions() *mcp.ClientOptions {
	return &mcp.ClientOptions{MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true}}
}

func TestMRTRElicitationTwoRounds(t *testing.T) {
	ctx := context.Background()
	cs := connectFixturesClient(t, ctx, manualRoundTripOptions())

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "test_input_required_result_elicitation"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.NeedsInput() {
		t.Fatal("round 1 should be input_required")
	}
	if blocks := substantiveText(res); len(blocks) != 0 {
		t.Errorf("input_required round must carry no substantive content, got %q", blocks)
	}
	if _, ok := res.InputRequests["user_name"].(*mcp.ElicitParams); !ok {
		t.Fatalf("expected an elicitation request under user_name, got %T", res.InputRequests["user_name"])
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
	if text := textOf(t, res); text != "Hello, Alice!" {
		t.Errorf("completion text = %q, want %q", text, "Hello, Alice!")
	}
}

// TestMRTRMissingResponseReRequests answers under the wrong key; the fixture
// must ask again rather than complete or error.
func TestMRTRMissingResponseReRequests(t *testing.T) {
	ctx := context.Background()
	cs := connectFixturesClient(t, ctx, manualRoundTripOptions())

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "test_input_required_result_elicitation",
		InputResponses: mcp.InputResponseMap{
			"wrong_key": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"data": "wrong"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.NeedsInput() {
		t.Fatal("a response under the wrong key must be answered with a re-request")
	}
	if _, ok := res.InputRequests["user_name"]; !ok {
		t.Error("the re-request must name user_name again")
	}
}

func TestMRTRTamperedStateRejected(t *testing.T) {
	ctx := context.Background()
	cs := connectFixturesClient(t, ctx, manualRoundTripOptions())

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "test_input_required_result_tampered_state"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.NeedsInput() || res.RequestState == "" {
		t.Fatal("round 1 should be input_required with a requestState")
	}

	_, err = cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "test_input_required_result_tampered_state",
		InputResponses: mcp.InputResponseMap{
			"confirm": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"ok": true}},
		},
		RequestState: res.RequestState + "-TAMPERED",
	})
	if err == nil {
		t.Fatal("a tampered requestState must be rejected with a JSON-RPC error")
	}
	if !strings.Contains(err.Error(), "integrity") {
		t.Errorf("rejection should say why: %v", err)
	}
}

func TestMRTRMultiRoundStatesDiffer(t *testing.T) {
	ctx := context.Background()
	cs := connectFixturesClient(t, ctx, manualRoundTripOptions())

	r1, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "test_input_required_result_multi_round"})
	if err != nil {
		t.Fatal(err)
	}
	if !r1.NeedsInput() || r1.RequestState == "" {
		t.Fatal("round 1 should be input_required with state")
	}

	r2, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "test_input_required_result_multi_round",
		InputResponses: mcp.InputResponseMap{
			"step1": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"name": "Alice"}},
		},
		RequestState: r1.RequestState,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !r2.NeedsInput() {
		t.Fatal("round 2 should be another input_required")
	}
	if r2.RequestState == r1.RequestState {
		t.Error("requestState must evolve between rounds")
	}

	r3, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "test_input_required_result_multi_round",
		InputResponses: mcp.InputResponseMap{
			"step2": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"color": "blue"}},
		},
		RequestState: r2.RequestState,
	})
	if err != nil {
		t.Fatal(err)
	}
	if r3.NeedsInput() {
		t.Fatal("round 3 should complete")
	}
	if text := textOf(t, r3); text != "Multi-round complete: Alice likes blue" {
		t.Errorf("completion text = %q", text)
	}
}

func TestMRTRStateHelperRoundTrip(t *testing.T) {
	state := signMRTRState("round=2;name=Alice")
	payload, err := verifyMRTRState(state)
	if err != nil {
		t.Fatalf("a state this process signed must verify: %v", err)
	}
	if payload != "round=2;name=Alice" {
		t.Errorf("payload = %q", payload)
	}
	for _, tampered := range []string{state + "-TAMPERED", state[:len(state)-1], "", "not-base64!"} {
		if _, err := verifyMRTRState(tampered); err == nil {
			t.Errorf("tampered state %q verified", tampered)
		}
	}
}

// TestMRTRCapabilitiesGating declares sampling (via a CreateMessageHandler) but
// not elicitation; the fixture must not ask for an elicitation.
func TestMRTRCapabilitiesGating(t *testing.T) {
	ctx := context.Background()
	opts := manualRoundTripOptions()
	opts.CreateMessageHandler = func(context.Context, *mcp.CreateMessageRequest) (*mcp.CreateMessageResult, error) {
		return &mcp.CreateMessageResult{
			Content: &mcp.TextContent{Text: "hi"}, Model: "test-model", Role: "assistant",
		}, nil
	}
	cs := connectFixturesClient(t, ctx, opts)

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "test_input_required_result_capabilities"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.NeedsInput() {
		t.Fatal("a sampling-capable client should be asked for input")
	}
	if _, ok := res.InputRequests["greeting"]; !ok {
		t.Error("sampling was declared, so a sampling request should be present")
	}
	for key, request := range res.InputRequests {
		if _, isElicit := request.(*mcp.ElicitParams); isElicit {
			t.Errorf("elicitation was not declared but request %q asks for it", key)
		}
	}
}

func TestMRTRPromptTwoRounds(t *testing.T) {
	ctx := context.Background()
	cs := connectFixturesClient(t, ctx, manualRoundTripOptions())

	r1, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{Name: "test_input_required_result_prompt"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r1.InputRequests) == 0 {
		t.Fatal("round 1 should ask for the prompt context")
	}
	if len(r1.Messages) != 0 {
		t.Error("input_required round must not carry messages")
	}

	r2, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{
		Name: "test_input_required_result_prompt",
		InputResponses: mcp.InputResponseMap{
			"user_context": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"context": "test context"}},
		},
		RequestState: r1.RequestState,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(r2.InputRequests) != 0 {
		t.Fatal("round 2 should complete")
	}
	if len(r2.Messages) == 0 {
		t.Error("a complete GetPromptResult must carry messages")
	}
}

// TestXMcpHeaderSurvivesToolsList pins the serialization question the SEP-2243
// scenario depends on: the x-mcp-header annotation must reach tools/list
// intact, or the suite reports the whole scenario untestable.
func TestXMcpHeaderSurvivesToolsList(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := buildConformanceServer(ctx, Config{Toolsets: []string{"all"}}, true, logger)
	if err != nil {
		t.Fatal(err)
	}
	tools, _ := listOverMemory(t, ctx, server)
	raw, ok := tools["test_x_mcp_header"]
	if !ok {
		t.Fatal("test_x_mcp_header is not served")
	}
	if !strings.Contains(string(raw), `"x-mcp-header":"Region"`) {
		t.Errorf("the x-mcp-header annotation did not survive to tools/list: %s", raw)
	}
}

// substantiveText returns the result's text blocks minus any guardrail
// decoration. The audit-only default policy attaches a "device policy warning"
// block on non-interactive hosts (CI runners, sandboxes); the conformance
// suite's checks search content rather than asserting block zero, so these
// tests apply the same tolerance and stay strict about everything else.
func substantiveText(res *mcp.CallToolResult) []string {
	var blocks []string
	for _, c := range res.Content {
		text, ok := c.(*mcp.TextContent)
		if !ok || strings.HasPrefix(text.Text, "device policy warning:") {
			continue
		}
		blocks = append(blocks, text.Text)
	}
	return blocks
}

func textOf(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	blocks := substantiveText(res)
	if len(blocks) == 0 {
		t.Fatal("result has no substantive text content")
	}
	return blocks[0]
}
