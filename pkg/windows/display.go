//go:build windows && (amd64 || arm64)

package windows

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

// DisplayInventory reports the connected monitors, their geometry, and DPI/scale.
func DisplayInventory() inventory.ServerTool {
	return NewToolFromHandler(
		ToolsetScreen,
		mcp.Tool{
			Name:        "DisplayInventory",
			Description: "List the connected displays with their bounds, work area, DPI, and scale percentage. Read-only. Useful for understanding the multi-monitor coordinate space used by Click/Move.",
			Annotations: &mcp.ToolAnnotations{Title: "Display inventory", ReadOnlyHint: true},
			InputSchema: &jsonschema.Schema{Type: "object"},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			displays, err := deps.Desktop().Displays()
			if err != nil {
				return NewToolResultErrorFromErr("failed to enumerate displays", err), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "%d display(s):\n", len(displays))
			for _, d := range displays {
				primary := ""
				if d.Primary {
					primary = " (primary)"
				}
				fmt.Fprintf(&b, "  [%d]%s %dx%d at (%d,%d), work %dx%d, DPI %d (%d%% scale)\n",
					d.Index, primary,
					d.Bounds.Width(), d.Bounds.Height(), d.Bounds.Left, d.Bounds.Top,
					d.WorkArea.Width(), d.WorkArea.Height(),
					d.DPI, d.ScalePct)
			}
			return NewToolResultText(b.String()), nil
		},
	)
}
