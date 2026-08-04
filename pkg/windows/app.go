//go:build windows && (amd64 || arm64)

package windows

import (
	"context"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

// App launches, switches to, or resizes applications and windows.
func App() inventory.ServerTool {
	destructive, openWorld := true, true
	return NewToolFromHandler(
		ToolsetApps,
		mcp.Tool{
			Name: "App",
			Description: "Manage applications and windows. mode=launch starts an app by name (e.g. \"notepad\", \"msedge\"); " +
				"mode=switch brings a window (matched by title substring) to the foreground; " +
				"mode=resize moves/resizes a matched window. " +
				"To start a program by full path, use LaunchExecutable (shell toolset).",
			// Destructive and open-world: a launch starts an arbitrary registered
			// application, and a URL-shaped name opens the browser. Without these a
			// policy gating "destructive" left both ungated.
			Annotations: &mcp.ToolAnnotations{
				Title:           "App / window control",
				ReadOnlyHint:    false,
				DestructiveHint: &destructive,
				OpenWorldHint:   &openWorld,
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"mode":        {Type: "string", Enum: []any{"launch", "switch", "resize"}, Description: "Operation."},
					"name":        {Type: "string", Description: "App name (launch) or window title substring (switch/resize)."},
					"window_loc":  {Type: "array", Description: "Target [x,y] for resize.", Items: &jsonschema.Schema{Type: "integer"}},
					"window_size": {Type: "array", Description: "Target [width,height] for resize.", Items: &jsonschema.Schema{Type: "integer"}},
				},
				Required: []string{"mode"},
			},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			mode, err := OptionalStringEnum(args, "mode", "", "launch", "switch", "resize")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			dsk := deps.Desktop()

			switch mode {
			case "launch":
				name, err := RequiredString(args, "name")
				if err != nil {
					return NewToolResultError(err.Error()), nil
				}
				// A URL-shaped name is a navigation, not an app launch: Start-Process
				// hands it to the default browser. Enforce HTTPS has to see it.
				if scheme, isURL := urlSchemeIfURL(name); isURL && scheme == "http" && deps.EnforceHTTPS() {
					return NewToolResultErrorf("%s: %q would open the default browser at a plaintext "+
						"address. Retry with an https:// URL.", ErrPlaintextHTTP, name), nil
				}
				if _, err := dsk.LaunchApp(ctx, name); err != nil {
					return NewToolResultErrorFromErr("launch failed", err), nil
				}
				return NewToolResultTextf("Launched %q.", name), nil

			case "switch":
				name, err := RequiredString(args, "name")
				if err != nil {
					return NewToolResultError(err.Error()), nil
				}
				w, err := dsk.ActivateWindow(name)
				if err != nil {
					return NewToolResultErrorFromErr("switch failed", err), nil
				}
				return NewToolResultTextf("Switched to %q [pid %d].", w.Title, w.ProcessID), nil

			case "resize":
				name, err := RequiredString(args, "name")
				if err != nil {
					return NewToolResultError(err.Error()), nil
				}
				loc, err := OptionalIntSlice(args, "window_loc")
				if err != nil {
					return NewToolResultError(err.Error()), nil
				}
				size, err := OptionalIntSlice(args, "window_size")
				if err != nil {
					return NewToolResultError(err.Error()), nil
				}
				if len(loc) < 2 || len(size) < 2 {
					return NewToolResultError("resize requires window_loc [x,y] and window_size [width,height]"), nil
				}
				w, err := dsk.ResizeWindow(name, loc[0], loc[1], size[0], size[1])
				if err != nil {
					return NewToolResultErrorFromErr("resize failed", err), nil
				}
				return NewToolResultTextf("Resized %q to %dx%d at (%d,%d).", w.Title, size[0], size[1], loc[0], loc[1]), nil

			default:
				return NewToolResultError("invalid mode"), nil
			}
		},
	)
}
