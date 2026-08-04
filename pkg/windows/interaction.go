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

// resolveLabel resolves a target to an interactive-element label, from an
// explicit "label" or by "name" (+ optional "control_type" / "nth") against the
// most recent Snapshot. Returns ok=false when no target key is present.
func resolveLabel(deps ToolDependencies, args map[string]any) (label int, ok bool, err error) {
	if v, present := args["label"]; present && v != nil {
		l, e := OptionalInt(args, "label", -1)
		if e != nil {
			return 0, false, e
		}
		return l, true, nil
	}
	if name := OptionalString(args, "name", ""); name != "" {
		ct := OptionalString(args, "control_type", "")
		nth, e := OptionalInt(args, "nth", 0)
		if e != nil {
			return 0, false, e
		}
		l, found := deps.Desktop().LabelForName(name, ct, nth)
		if !found {
			return 0, false, fmt.Errorf("no element named %q found in the last Snapshot; take a fresh Snapshot", name)
		}
		return l, true, nil
	}
	return 0, false, nil
}

// resolveTarget resolves a click point from an explicit "loc" [x,y], a "label",
// or a "name" (+ optional "control_type"/"nth") from the most recent Snapshot.
// It returns ok=false when no target is provided.
func resolveTarget(deps ToolDependencies, args map[string]any) (x, y int, ok bool, err error) {
	if loc, e := OptionalIntSlice(args, "loc"); e != nil {
		return 0, 0, false, e
	} else if len(loc) >= 2 {
		return loc[0], loc[1], true, nil
	}
	label, ok, err := resolveLabel(deps, args)
	if err != nil || !ok {
		return 0, 0, false, err
	}
	cx, cy, found := deps.Desktop().CoordinatesForLabel(label)
	if !found {
		return 0, 0, false, fmt.Errorf("label %d not found in the last Snapshot; take a fresh Snapshot first", label)
	}
	return cx, cy, true, nil
}

// targetSchema is the shared loc/label/name input for interaction tools.
func targetSchema(extra map[string]*jsonschema.Schema) *jsonschema.Schema {
	props := map[string]*jsonschema.Schema{
		"loc": {
			Type:        "array",
			Description: "Explicit screen coordinates [x, y] in physical pixels.",
			Items:       &jsonschema.Schema{Type: "integer"},
		},
		"label": {
			Type:        "integer",
			Description: "Interactive element label from the most recent Snapshot.",
		},
		"name": {
			Type:        "string",
			Description: "Target an element by its accessible name from the most recent Snapshot (alternative to 'label').",
		},
		"control_type": {
			Type:        "string",
			Description: "Optional control type to disambiguate a 'name' match (e.g. Button, Edit, ListItem, TabItem).",
		},
		"nth": {
			Type:        "integer",
			Description: "Optional 0-based index to pick among multiple 'name' matches (default 0).",
		},
	}
	for k, v := range extra {
		props[k] = v
	}
	return &jsonschema.Schema{Type: "object", Properties: props}
}

// Click clicks a UI element identified by label (from Snapshot) or explicit
// coordinates.
//
// Destructive: a click is what presses "Delete", "Send" and "Confirm". The button
// it lands on is not knowable from the arguments, so the annotation has to assume
// the worst — a rule that gates Type but not Click gates nothing much.
func Click() inventory.ServerTool {
	destructive := true
	return NewToolFromHandler(
		ToolsetInteraction,
		mcp.Tool{
			Name:        "Click",
			Description: "Click a UI element by its Snapshot label or explicit [x,y] coordinates. Supports left/right/middle button and single/double click (clicks=0 hovers).",
			Annotations: &mcp.ToolAnnotations{Title: "Click", ReadOnlyHint: false, DestructiveHint: &destructive},
			InputSchema: targetSchema(map[string]*jsonschema.Schema{
				"button": {Type: "string", Enum: []any{"left", "right", "middle"}, Description: "Mouse button (default left)."},
				"clicks": {Type: "integer", Description: "0 = hover, 1 = single (default), 2 = double."},
			}),
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			x, y, ok, err := resolveTarget(deps, args)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			if !ok {
				return NewToolResultError("provide 'label' or 'loc' [x,y]"), nil
			}
			button, err := OptionalStringEnum(args, "button", "left", "left", "right", "middle")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			clicks, err := OptionalInt(args, "clicks", 1)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			if err := deps.Desktop().Click(x, y, button, clicks); err != nil {
				return NewToolResultErrorFromErr("click failed", err), nil
			}
			verb := "Clicked"
			if clicks == 0 {
				verb = "Hovered"
			} else if clicks == 2 {
				verb = "Double-clicked"
			}
			return NewToolResultTextf("%s at (%d,%d) with %s button.", verb, x, y, button), nil
		},
	)
}

// Type types text, optionally after clicking a target element first.
func Type() inventory.ServerTool {
	destructive := true
	return NewToolFromHandler(
		ToolsetInteraction,
		mcp.Tool{
			Name:        "Type",
			Description: "Type text at the current focus, or first click a target (by label or [x,y]) and then type. Optionally clear the field first and/or press Enter after.",
			Annotations: &mcp.ToolAnnotations{Title: "Type text", ReadOnlyHint: false, DestructiveHint: &destructive},
			InputSchema: targetSchema(map[string]*jsonschema.Schema{
				"text":        {Type: "string", Description: "The text to type."},
				"clear":       {Type: "boolean", Description: "Select-all and delete before typing (default false)."},
				"press_enter": {Type: "boolean", Description: "Press Enter after typing (default false)."},
			}),
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			text := OptionalString(args, "text", "")
			x, y, ok, err := resolveTarget(deps, args)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			dsk := deps.Desktop()
			if ok {
				if err := dsk.Click(x, y, "left", 1); err != nil {
					return NewToolResultErrorFromErr("failed to focus target", err), nil
				}
			}
			if OptionalBool(args, "clear", false) {
				if err := dsk.SendShortcut([]string{"ctrl", "a"}); err != nil {
					return NewToolResultErrorFromErr("failed to select all", err), nil
				}
				if err := dsk.SendShortcut([]string{"delete"}); err != nil {
					return NewToolResultErrorFromErr("failed to clear", err), nil
				}
			}
			if err := dsk.TypeText(text); err != nil {
				return NewToolResultErrorFromErr("failed to type", err), nil
			}
			if OptionalBool(args, "press_enter", false) {
				if err := dsk.SendShortcut([]string{"enter"}); err != nil {
					return NewToolResultErrorFromErr("failed to press enter", err), nil
				}
			}
			return NewToolResultTextf("Typed %d character(s).", len([]rune(text))), nil
		},
	)
}

// Scroll scrolls the wheel at a target or the current cursor position.
//
// Destructive, which is the less obvious of the input annotations: a wheel notch
// over a Windows combo box changes the selection and over a spinner changes the
// value. Scroll targets a point, not a control type, so it cannot know which it
// is landing on — a silent field edit is within reach of a tool that reads as
// pure navigation.
func Scroll() inventory.ServerTool {
	destructive := true
	return NewToolFromHandler(
		ToolsetInteraction,
		mcp.Tool{
			Name:        "Scroll",
			Description: "Scroll the mouse wheel at a target element (by label or [x,y]) or the current cursor position. Direction up/down/left/right; wheel_times is the number of notches.",
			Annotations: &mcp.ToolAnnotations{Title: "Scroll", ReadOnlyHint: false, DestructiveHint: &destructive},
			InputSchema: targetSchema(map[string]*jsonschema.Schema{
				"direction":   {Type: "string", Enum: []any{"up", "down", "left", "right"}, Description: "Scroll direction (default down)."},
				"wheel_times": {Type: "integer", Description: "Number of wheel notches (default 1)."},
			}),
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			x, y, ok, err := resolveTarget(deps, args)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			if !ok {
				return NewToolResultError("provide 'label' or 'loc' [x,y] to scroll at"), nil
			}
			direction, err := OptionalStringEnum(args, "direction", "down", "up", "down", "left", "right")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			wheelTimes, err := OptionalInt(args, "wheel_times", 1)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			if err := deps.Desktop().Scroll(x, y, wheelTimes, direction); err != nil {
				return NewToolResultErrorFromErr("scroll failed", err), nil
			}
			return NewToolResultTextf("Scrolled %s %d notch(es) at (%d,%d).", direction, wheelTimes, x, y), nil
		},
	)
}

// Move moves the cursor to a target element or coordinates (hover).
//
// Deliberately NOT destructive, and the only input tool that is not. Moving the
// cursor commits nothing: it can open a hover menu, but acting on one still needs
// a Click, which is gated. Annotating every input tool destructive regardless of
// what it does would make `annotation: destructive` mean "input" and cost
// operators the ability to gate the calls that actually change state.
func Move() inventory.ServerTool {
	return NewToolFromHandler(
		ToolsetInteraction,
		mcp.Tool{
			Name:        "Move",
			Description: "Move the mouse cursor to a target element (by label) or explicit [x,y] coordinates, without clicking.",
			Annotations: &mcp.ToolAnnotations{Title: "Move cursor", ReadOnlyHint: false},
			InputSchema: targetSchema(nil),
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			x, y, ok, err := resolveTarget(deps, args)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			if !ok {
				return NewToolResultError("provide 'label' or 'loc' [x,y]"), nil
			}
			if err := deps.Desktop().MoveCursor(x, y); err != nil {
				return NewToolResultErrorFromErr("move failed", err), nil
			}
			return NewToolResultTextf("Moved cursor to (%d,%d).", x, y), nil
		},
	)
}

// Shortcut sends a keyboard chord like "ctrl+shift+esc".
func Shortcut() inventory.ServerTool {
	destructive := true
	return NewToolFromHandler(
		ToolsetInteraction,
		mcp.Tool{
			Name:        "Shortcut",
			Description: "Press a keyboard shortcut chord, e.g. \"ctrl+c\", \"alt+tab\", \"ctrl+shift+esc\", \"win+r\". Keys are joined with '+'.",
			Annotations: &mcp.ToolAnnotations{Title: "Keyboard shortcut", ReadOnlyHint: false, DestructiveHint: &destructive},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"shortcut": {Type: "string", Description: "The chord, e.g. \"ctrl+shift+esc\"."},
				},
				Required: []string{"shortcut"},
			},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			shortcut, err := RequiredString(args, "shortcut")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			keys := make([]string, 0, 4)
			for _, k := range strings.Split(shortcut, "+") {
				if t := strings.TrimSpace(k); t != "" {
					keys = append(keys, t)
				}
			}
			if len(keys) == 0 {
				return NewToolResultError("empty shortcut"), nil
			}
			if err := deps.Desktop().SendShortcut(keys); err != nil {
				return NewToolResultErrorFromErr("shortcut failed", err), nil
			}
			return NewToolResultTextf("Pressed %s.", strings.Join(keys, "+")), nil
		},
	)
}
