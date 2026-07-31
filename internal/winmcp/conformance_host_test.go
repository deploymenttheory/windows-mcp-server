//go:build windows && (amd64 || arm64) && conformance

package winmcp

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestConformanceHostServesTheShippedSurface is what makes the conformance
// evidence transfer.
//
// The official suite can only reach a server over HTTP, so it is measured against
// the conformance host rather than the stdio binary operators actually run. That
// only proves something about the shipped server if the two serve the same thing.
// This test connects to the host's server object over an in-memory transport and
// compares the tool manifest and declared capabilities, byte for byte, with what
// CaptureSurface records from the stdio construction.
//
// Fixtures are off here on purpose: with them on the manifests are *meant* to
// differ, and that difference is exactly why the suite is run twice and the two
// results recorded separately.
func TestConformanceHostServesTheShippedSurface(t *testing.T) {
	ctx := context.Background()
	cfg := Config{Toolsets: []string{"all"}}

	stdio, err := CaptureSurface(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := buildConformanceServer(ctx, cfg, false, logger)
	if err != nil {
		t.Fatal(err)
	}
	hostTools, hostCaps := listOverMemory(t, ctx, server)

	if diff := diffToolNames(stdio.ToolsListResult, hostTools); diff != "" {
		t.Errorf("conformance host and stdio server serve different tools: %s", diff)
	}
	if string(canonical(t, stdio.Capabilities)) != string(canonical(t, hostCaps)) {
		t.Errorf("declared capabilities differ:\n stdio: %s\n  host: %s",
			canonical(t, stdio.Capabilities), canonical(t, hostCaps))
	}
}

// TestConformanceFixturesAreAdditive checks that enabling fixtures adds names and
// changes nothing else. A fixture that displaced or altered a product tool would
// make the depth pass quietly measure something other than this server.
func TestConformanceFixturesAreAdditive(t *testing.T) {
	ctx := context.Background()
	cfg := Config{Toolsets: []string{"all"}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	plain, err := buildConformanceServer(ctx, cfg, false, logger)
	if err != nil {
		t.Fatal(err)
	}
	withFixtures, err := buildConformanceServer(ctx, cfg, true, logger)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := listOverMemory(t, ctx, plain)
	extended, _ := listOverMemory(t, ctx, withFixtures)

	got := map[string]json.RawMessage{}
	for name, raw := range extended {
		got[name] = raw
	}
	for name, raw := range base {
		fixture, ok := got[name]
		if !ok {
			t.Errorf("fixtures removed the product tool %q", name)
			continue
		}
		if string(fixture) != string(raw) {
			t.Errorf("fixtures altered the product tool %q", name)
		}
		delete(got, name)
	}
	if len(got) == 0 {
		t.Error("--fixtures registered nothing; the depth pass would measure the product manifest")
	}
	// Every added tool must be one the suite actually names. An allowlist rather
	// than a `test_` prefix check: the suite dictates these names and not all of
	// them follow that convention (json_schema_2020_12_tool does not), so a prefix
	// heuristic would either reject a required fixture or, loosened, stop catching
	// a product tool slipping in under the tag.
	suiteFixtures := map[string]bool{
		"test_simple_text":            true,
		"test_image_content":          true,
		"test_audio_content":          true,
		"test_multiple_content_types": true,
		"test_embedded_resource":      true,
		"test_error_handling":         true,
		"test_tool_with_progress":     true,
		"test_missing_capability":     true,
		"test_logging_tool":           true,
		"json_schema_2020_12_tool":    true,
	}
	for name := range got {
		if !suiteFixtures[name] {
			t.Errorf("fixture %q is not a name the conformance suite asks for; "+
				"fixtures exist to satisfy the suite, not to extend the manifest", name)
		}
	}
}

// listOverMemory runs a real MCP session against the server and returns the
// served tools keyed by name, plus the declared capabilities.
func listOverMemory(t *testing.T, ctx context.Context, server *mcp.Server) (map[string]json.RawMessage, json.RawMessage) {
	t.Helper()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ss.Close() }()

	client := mcp.NewClient(&mcp.Implementation{Name: "equivalence", Version: "test"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()

	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	tools := map[string]json.RawMessage{}
	for _, tool := range res.Tools {
		raw, err := json.Marshal(tool)
		if err != nil {
			t.Fatal(err)
		}
		tools[tool.Name] = raw
	}

	var caps json.RawMessage
	if init := cs.InitializeResult(); init != nil && init.Capabilities != nil {
		if caps, err = json.Marshal(init.Capabilities); err != nil {
			t.Fatal(err)
		}
	}
	return tools, caps
}

// diffToolNames compares a captured tools/list payload against the host's tools,
// reporting the first difference rather than dumping both manifests.
func diffToolNames(captured json.RawMessage, host map[string]json.RawMessage) string {
	var payload struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(captured, &payload); err != nil {
		return "could not decode captured tools/list: " + err.Error()
	}
	seen := map[string]bool{}
	for _, raw := range payload.Tools {
		var named struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(raw, &named); err != nil {
			return "could not decode a captured tool: " + err.Error()
		}
		seen[named.Name] = true
		hostTool, ok := host[named.Name]
		if !ok {
			return "stdio serves " + named.Name + " but the conformance host does not"
		}
		if string(hostTool) != string(raw) {
			return "definition of " + named.Name + " differs between transports"
		}
	}
	for name := range host {
		if !seen[name] {
			return "the conformance host serves " + name + " but stdio does not"
		}
	}
	return ""
}

// canonical re-marshals through a generic value so key order cannot make two
// equivalent capability objects compare unequal.
func canonical(t *testing.T, raw json.RawMessage) json.RawMessage {
	t.Helper()
	if len(raw) == 0 {
		return raw
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
