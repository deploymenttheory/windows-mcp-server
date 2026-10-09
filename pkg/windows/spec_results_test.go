//go:build windows && (amd64 || arm64)

package windows

import (
	"context"
	"encoding/base64"
	"path/filepath"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/mcp-server-core/mcpspec"
	"github.com/deploymenttheory/mcp-server-core/surface"
)

// OS-backed handlers use these constructors. Validate their actual wire
// responses after SDK decoration, without needing desktop permissions in CI.
func TestProductResultShapesMatchLatestSpec(t *testing.T) {
	dir := filepath.Join("..", "..", "schema")
	manifest, err := mcpspec.LoadManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := mcpspec.Load(dir, manifest.Newest())
	if err != nil {
		t.Fatal(err)
	}
	png, err := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9T7ZkAAAAASUVORK5CYII=")
	if err != nil {
		t.Fatal(err)
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "result-probe", Version: "test"},
		&mcp.ServerOptions{Capabilities: surface.PinnedCapabilities()})
	for _, tc := range []struct {
		name   string
		result *mcp.CallToolResult
	}{
		{"text", NewToolResultText("ready")},
		{"image", NewToolResultImage("Screenshot", png, "image/png")},
		{"error", NewToolResultError("unavailable")},
	} {
		server.AddTool(&mcp.Tool{Name: tc.name, InputSchema: &jsonschema.Schema{Type: "object"}},
			func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) { return tc.result, nil })
	}
	jsonResource, err := jsonResult("windows://system/info", map[string]any{"ready": true})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, uri string
		result    *mcp.ReadResourceResult
	}{
		{"text", "windows://desktop/snapshot", textResult("windows://desktop/snapshot", "text/plain", "ready")},
		{"json", "windows://system/info", jsonResource},
	} {
		server.AddResource(&mcp.Resource{Name: tc.name, URI: tc.uri},
			func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
				return tc.result, nil
			})
	}
	results, err := surface.CaptureRawResults(context.Background(), server, func(ctx context.Context, client *mcp.ClientSession) error {
		for _, name := range []string{"text", "image", "error"} {
			if _, err := client.CallTool(ctx, &mcp.CallToolParams{Name: name}); err != nil {
				return err
			}
		}
		for _, uri := range []string{"windows://desktop/snapshot", "windows://system/info"} {
			if _, err := client.ReadResource(ctx, &mcp.ReadResourceParams{URI: uri}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for method, want := range map[string]int{"tools/call": 3, "resources/read": 2} {
		if len(results[method]) != want {
			t.Errorf("%s produced %d responses, want %d", method, len(results[method]), want)
		}
		for _, raw := range results[method] {
			if err := surface.ValidateMethodResult(spec, method, raw); err != nil {
				t.Errorf("%s: %v", method, err)
			}
		}
	}
}
