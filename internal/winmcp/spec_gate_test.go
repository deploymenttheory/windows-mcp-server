//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/mcp-server-core/mcpspec"
	"github.com/deploymenttheory/mcp-server-core/surface"
)

// TestProductSpecGate validates the actual all-toolsets manifest and safe
// registered operations against the latest vendored published MCP revision.
func TestProductSpecGate(t *testing.T) {
	dir := filepath.Join("..", "..", "schema")
	manifest, err := mcpspec.LoadManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := mcpspec.Load(dir, manifest.Newest())
	if err != nil {
		t.Fatal(err)
	}
	var promptCount int
	got, err := captureSurfaceWithProbes(context.Background(), Config{Toolsets: []string{"all"}, Version: "test"},
		func(ctx context.Context, client *mcp.ClientSession) error {
			wait, err := client.CallTool(ctx, &mcp.CallToolParams{Name: "Wait", Arguments: map[string]any{"duration": 0}})
			if err != nil {
				return fmt.Errorf("call safe product tool: %w", err)
			}
			if wait.IsError {
				return fmt.Errorf("safe product tool Wait returned an error result")
			}
			listed, err := client.ListPrompts(ctx, nil)
			if err != nil {
				return err
			}
			promptCount = len(listed.Prompts)
			for _, prompt := range listed.Prompts {
				args := map[string]string{}
				for _, arg := range prompt.Arguments {
					if arg.Required {
						args[arg.Name] = "conformance probe"
					}
				}
				if _, err := client.GetPrompt(ctx, &mcp.GetPromptParams{Name: prompt.Name, Arguments: args}); err != nil {
					return fmt.Errorf("get prompt %q: %w", prompt.Name, err)
				}
			}
			if promptCount == 0 || len(listed.Prompts[0].Arguments) == 0 {
				return fmt.Errorf("no prompt argument available for completion probe")
			}
			_, err = client.Complete(ctx, &mcp.CompleteParams{
				Ref:      &mcp.CompleteReference{Type: "ref/prompt", Name: listed.Prompts[0].Name},
				Argument: mcp.CompleteParamsArgument{Name: listed.Prompts[0].Arguments[0].Name, Value: ""},
			})
			return err
		})
	if err != nil {
		t.Fatal(err)
	}
	if err := surface.RequireProbeMethods(got, "tools/call", "prompts/get", "completion/complete"); err != nil {
		t.Fatal(err)
	}
	if len(got.Results["prompts/get"]) != promptCount {
		t.Fatalf("probed %d of %d advertised prompts", len(got.Results["prompts/get"]), promptCount)
	}
	if err := surface.ValidateCaptured(spec, got); err != nil {
		t.Fatal(err)
	}
}
