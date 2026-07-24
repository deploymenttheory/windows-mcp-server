//go:build windows && (amd64 || arm64)

package windows

import (
	"context"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

// Screenshot captures the whole virtual desktop as a PNG image. Read-only.
func Screenshot() inventory.ServerTool {
	return NewToolFromHandler(
		ToolsetScreen,
		mcp.Tool{
			Name:        "Screenshot",
			Description: "Capture the entire virtual desktop (all monitors) as a PNG image. Read-only. Coordinates from Snapshot are in physical pixels; if the image was downscaled, multiply image coordinates by the reported scale factor before using them with Click/Move.",
			Annotations: &mcp.ToolAnnotations{
				Title:        "Screenshot",
				ReadOnlyHint: true,
			},
			InputSchema: &jsonschema.Schema{Type: "object"},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			pngData, w, h, denom, err := deps.Desktop().Screenshot()
			if err != nil {
				return NewToolResultErrorFromErr("screenshot failed", err), nil
			}
			caption := fmt.Sprintf("Screenshot %dx%d", w, h)
			if denom > 1 {
				caption += fmt.Sprintf(" (downscaled %dx; multiply image coordinates by %d for physical pixels)", denom, denom)
			}
			return NewToolResultImage(caption, pngData, "image/png"), nil
		},
	)
}
