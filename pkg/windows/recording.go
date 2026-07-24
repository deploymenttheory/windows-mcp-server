//go:build windows && (amd64 || arm64)

package windows

import (
	"context"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

// Recording reports on and annotates the session video recording. Recording is
// enabled server-side (--record-dir) so every session is tracked; this tool lets
// the agent confirm it is being recorded and mark the timeline with step labels.
func Recording() inventory.ServerTool {
	return NewToolFromHandler(
		ToolsetScreen,
		mcp.Tool{
			Name:        "Recording",
			Description: "Query or annotate the session video recording. mode=status reports whether the session is being recorded, the output file, frame count, and duration. mode=mark adds a labeled marker to the recording timeline so journey steps align with the video (written to a sidecar .jsonl log). Recording is enabled with the server's --record-dir flag.",
			Annotations: &mcp.ToolAnnotations{Title: "Session recording", ReadOnlyHint: true},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"mode":  {Type: "string", Enum: []any{"status", "mark"}, Description: "status (default) or mark."},
					"label": {Type: "string", Description: "Marker label (required for mode=mark), e.g. the journey step name."},
				},
			},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			mode, err := OptionalStringEnum(args, "mode", "status", "status", "mark")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			dsk := deps.Desktop()

			switch mode {
			case "mark":
				label := OptionalString(args, "label", "")
				if label == "" {
					return NewToolResultError("'label' is required for mode=mark"), nil
				}
				if !dsk.MarkRecording(label) {
					return NewToolResultText("Session is not being recorded; marker ignored."), nil
				}
				return NewToolResultTextf("Marked recording: %q", label), nil
			default:
				status, active := dsk.RecordingStatus()
				if !active {
					return NewToolResultText("Session recording: OFF (start the server with --record-dir to record)."), nil
				}
				return NewToolResultText(fmt.Sprintf(
					"Session recording: ON\nFile: %s\nMarkers: %s\nFrames: %d @ %d fps\nDuration: %.1fs",
					status.VideoPath, status.MarkersPath, status.Frames, status.FPS, status.DurationSec,
				)), nil
			}
		},
	)
}
