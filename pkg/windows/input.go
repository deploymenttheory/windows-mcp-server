//go:build windows && (amd64 || arm64)

package windows

import (
	"context"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

// Wait pauses for a fixed number of seconds. It is a read-only interaction tool
// used to let the UI settle between actions.
func Wait() inventory.ServerTool {
	return NewToolFromHandler(
		ToolsetInteraction,
		mcp.Tool{
			Name:        "Wait",
			Description: "Pause for a fixed number of seconds. Use between actions to let the UI settle before the next Snapshot or interaction.",
			Annotations: &mcp.ToolAnnotations{
				Title:        "Wait",
				ReadOnlyHint: true,
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"duration": {
						Type:        "integer",
						Description: "Number of seconds to wait (clamped to 0-60).",
					},
				},
				Required: []string{"duration"},
			},
		},
		func(ctx context.Context, _ ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			duration, err := OptionalInt(args, "duration", 0)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			if duration < 0 {
				duration = 0
			}
			if duration > 60 {
				duration = 60
			}
			select {
			case <-time.After(time.Duration(duration) * time.Second):
			case <-ctx.Done():
				return NewToolResultError("wait cancelled"), nil
			}
			return NewToolResultTextf("Waited %d second(s).", duration), nil
		},
	)
}
