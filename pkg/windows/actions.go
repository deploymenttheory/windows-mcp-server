//go:build windows && (amd64 || arm64)

package windows

import (
	"context"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

// Invoke acts on a UI element through its accessibility control pattern rather
// than by synthesizing input. This is the reliable, RPA-preferred path.
//
// Destructive, and load-bearingly so: invoke presses buttons and set_value fills
// fields, which is what Type does and more reliably. Without the hint every rule
// and rate limit matching `annotation: destructive` missed it — while the persona
// instructions this server ships tell the model to prefer Invoke over Type, which
// steered the model off the gated path onto the ungated one.
func Invoke() inventory.ServerTool {
	destructive := true
	return NewToolFromHandler(
		ToolsetInteraction,
		mcp.Tool{
			Name: "Invoke",
			Description: "Act on a UI element via its accessibility control pattern instead of synthetic mouse/keyboard input — " +
				"more reliable and independent of window focus, occlusion, or DPI. Target by 'label' from the latest Snapshot. " +
				"actions: invoke (buttons, links, menu items), set_value (text fields — provide 'value', types instantly), " +
				"toggle (checkboxes/switches), select (list items, radio buttons, tabs), expand / collapse (combo boxes, tree " +
				"items). If an element does not support the pattern this returns an error — fall back to Click/Type.",
			Annotations: &mcp.ToolAnnotations{
				Title:           "Invoke UI element (pattern)",
				ReadOnlyHint:    false,
				DestructiveHint: &destructive,
			},
			InputSchema: targetSchema(map[string]*jsonschema.Schema{
				"action": {Type: "string", Enum: []any{"invoke", "set_value", "toggle", "select", "expand", "collapse"}, Description: "The pattern action (default invoke)."},
				"value":  {Type: "string", Description: "Text to set (required for set_value)."},
			}),
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			label, ok, err := resolveLabel(deps, args)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			if !ok {
				return NewToolResultError("provide 'label' or 'name' (take a Snapshot first)"), nil
			}
			action, err := OptionalStringEnum(args, "action", "invoke", "invoke", "set_value", "toggle", "select", "expand", "collapse")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			dsk := deps.Desktop()

			switch action {
			case "invoke":
				err = dsk.InvokeLabel(label)
			case "set_value":
				err = dsk.SetValueLabel(label, OptionalString(args, "value", ""))
			case "toggle":
				err = dsk.ToggleLabel(label)
			case "select":
				err = dsk.SelectLabel(label)
			case "expand":
				err = dsk.ExpandLabel(label)
			case "collapse":
				err = dsk.CollapseLabel(label)
			default:
				return NewToolResultError("invalid action"), nil
			}
			if err != nil {
				return NewToolResultErrorFromErr(action+" failed", err), nil
			}
			return NewToolResultTextf("%s on element [%d] succeeded.", action, label), nil
		},
	)
}

// GetText reads a labeled element's name and value (via UIA), for verification.
func GetText() inventory.ServerTool {
	return NewToolFromHandler(
		ToolsetInteraction,
		mcp.Tool{
			Name:        "GetText",
			Description: "Read a UI element's name and value via UI Automation, for precise verification (e.g. confirm a field shows the expected text). Target by 'label' from the latest Snapshot. Read-only.",
			Annotations: &mcp.ToolAnnotations{Title: "Read element text", ReadOnlyHint: true},
			InputSchema: targetSchema(nil),
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			label, ok, err := resolveLabel(deps, args)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			if !ok {
				return NewToolResultError("provide 'label' or 'name'"), nil
			}
			name, value, err := deps.Desktop().ReadLabel(label)
			if err != nil {
				return NewToolResultErrorFromErr("failed to read element", err), nil
			}
			return NewToolResultTextf("name: %q\nvalue: %q", name, value), nil
		},
	)
}
