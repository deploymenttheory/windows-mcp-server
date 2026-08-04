//go:build windows && (amd64 || arm64)

package windows

import (
	"context"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

// Clipboard gets or sets the Windows clipboard's Unicode text.
//
// Destructive on both modes, for different reasons. set overwrites a buffer the
// user owns and cannot recover. get is the one that matters more: the clipboard
// is one of the three channels the credential never-read invariant exists to
// defeat (see internal/desktop/credentials.go, requireMaskedFocus), so a get is a
// read of whatever a password manager last placed there. The invariant holds at
// the Credentials tool; this is the way around the reasoning behind it, and it
// belongs behind the same gate.
func Clipboard() inventory.ServerTool {
	destructive := true
	return NewToolFromHandler(
		ToolsetSystem,
		mcp.Tool{
			Name:        "Clipboard",
			Description: "Get or set the Windows clipboard text. mode=get returns the current clipboard text; mode=set replaces it with the provided text.",
			Annotations: &mcp.ToolAnnotations{
				Title:           "Clipboard get/set",
				ReadOnlyHint:    false,
				DestructiveHint: &destructive,
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"mode": {
						Type:        "string",
						Enum:        []any{"get", "set"},
						Description: "Operation: 'get' to read, 'set' to write.",
					},
					"text": {
						Type:        "string",
						Description: "Text to place on the clipboard (required when mode=set).",
					},
				},
				Required: []string{"mode"},
			},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			mode, err := OptionalStringEnum(args, "mode", "", "get", "set")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}

			switch mode {
			case "get":
				text, err := deps.Desktop().ClipboardGet()
				if err != nil {
					return NewToolResultErrorFromErr("failed to read clipboard", err), nil
				}
				return NewToolResultText(text), nil
			case "set":
				text := OptionalString(args, "text", "")
				if err := deps.Desktop().ClipboardSet(text); err != nil {
					return NewToolResultErrorFromErr("failed to set clipboard", err), nil
				}
				return NewToolResultTextf("Copied %d character(s) to the clipboard.", len([]rune(text))), nil
			default:
				return NewToolResultError("mode must be 'get' or 'set'"), nil
			}
		},
	)
}
