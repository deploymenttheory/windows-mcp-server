//go:build windows && (amd64 || arm64)

package windows

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/internal/desktop"
	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

// pointForLabelOrLoc resolves a click point from a label (int) or a [x,y] loc.
func pointForLabelOrLoc(deps ToolDependencies, v any) (int, int, bool) {
	switch t := v.(type) {
	case float64:
		if x, y, ok := deps.Desktop().CoordinatesForLabel(int(t)); ok {
			return x, y, true
		}
	case []any:
		if len(t) >= 2 {
			x, xok := t[0].(float64)
			y, yok := t[1].(float64)
			if xok && yok {
				return int(x), int(y), true
			}
		}
	}
	return 0, 0, false
}

// MultiSelect Ctrl-clicks several elements (by label) or points to build a
// multi-selection.
func MultiSelect() inventory.ServerTool {
	return NewToolFromHandler(
		ToolsetInteraction,
		mcp.Tool{
			Name:        "MultiSelect",
			Description: "Select multiple UI elements at once by Ctrl-clicking each. Provide 'labels' (from Snapshot) or 'locs' ([[x,y],...]).",
			Annotations: &mcp.ToolAnnotations{Title: "Multi-select", ReadOnlyHint: false},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"labels":    {Type: "array", Description: "Element labels to select.", Items: &jsonschema.Schema{Type: "integer"}},
					"locs":      {Type: "array", Description: "Points [[x,y],...] to select.", Items: &jsonschema.Schema{Type: "array", Items: &jsonschema.Schema{Type: "integer"}}},
					"hold_ctrl": {Type: "boolean", Description: "Hold Ctrl while clicking (default true)."},
				},
			},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			points, err := collectPoints(deps, args)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			if len(points) == 0 {
				return NewToolResultError("provide 'labels' or 'locs'"), nil
			}
			holdCtrl := OptionalBool(args, "hold_ctrl", true)
			if err := deps.Desktop().ClickMany(points, holdCtrl); err != nil {
				return NewToolResultErrorFromErr("multi-select failed", err), nil
			}
			return NewToolResultTextf("Selected %d element(s).", len(points)), nil
		},
	)
}

// collectPoints resolves the "labels" and "locs" arguments into click points.
func collectPoints(deps ToolDependencies, args map[string]any) ([][2]int, error) {
	var points [][2]int
	if raw, ok := args["labels"].([]any); ok {
		for _, v := range raw {
			f, ok := v.(float64)
			if !ok {
				return nil, fmt.Errorf("labels must be integers")
			}
			x, y, found := deps.Desktop().CoordinatesForLabel(int(f))
			if !found {
				return nil, fmt.Errorf("label %d not found in the last Snapshot", int(f))
			}
			points = append(points, [2]int{x, y})
		}
	}
	if raw, ok := args["locs"].([]any); ok {
		for _, v := range raw {
			pair, ok := v.([]any)
			if !ok || len(pair) < 2 {
				return nil, fmt.Errorf("each loc must be [x,y]")
			}
			x, xok := pair[0].(float64)
			y, yok := pair[1].(float64)
			if !xok || !yok {
				return nil, fmt.Errorf("loc coordinates must be integers")
			}
			points = append(points, [2]int{int(x), int(y)})
		}
	}
	return points, nil
}

// MultiEdit types into several fields in sequence, clearing each first.
func MultiEdit() inventory.ServerTool {
	destructive := true
	return NewToolFromHandler(
		ToolsetInteraction,
		mcp.Tool{
			Name:        "MultiEdit",
			Description: "Fill multiple input fields in one call. Provide 'edits' as [[label, text], ...] (label from Snapshot) or [[x, y, text], ...]. Each field is clicked, cleared, and typed into.",
			Annotations: &mcp.ToolAnnotations{Title: "Multi-edit fields", ReadOnlyHint: false, DestructiveHint: &destructive},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"edits": {Type: "array", Description: "[[label,text],...] or [[x,y,text],...]", Items: &jsonschema.Schema{Type: "array"}},
				},
				Required: []string{"edits"},
			},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			raw, ok := args["edits"].([]any)
			if !ok || len(raw) == 0 {
				return NewToolResultError("provide 'edits' as a non-empty array"), nil
			}
			dsk := deps.Desktop()
			done := 0
			for _, item := range raw {
				pair, ok := item.([]any)
				if !ok || len(pair) < 2 {
					return NewToolResultError("each edit must be [label,text] or [x,y,text]"), nil
				}
				var x, y int
				var text string
				if len(pair) == 2 {
					// [label, text]
					xx, yy, found := pointForLabelOrLoc(deps, pair[0])
					if !found {
						return NewToolResultErrorf("could not resolve target %v (take a fresh Snapshot)", pair[0]), nil
					}
					x, y = xx, yy
					text, _ = pair[1].(string)
				} else {
					// [x, y, text]
					fx, _ := pair[0].(float64)
					fy, _ := pair[1].(float64)
					x, y = int(fx), int(fy)
					text, _ = pair[2].(string)
				}
				if err := dsk.Click(x, y, "left", 1); err != nil {
					return NewToolResultErrorFromErr("failed to focus field", err), nil
				}
				_ = dsk.SendShortcut([]string{"ctrl", "a"})
				_ = dsk.SendShortcut([]string{"delete"})
				if err := dsk.TypeText(text); err != nil {
					return NewToolResultErrorFromErr("failed to type", err), nil
				}
				done++
				time.Sleep(50 * time.Millisecond)
			}
			return NewToolResultTextf("Edited %d field(s).", done), nil
		},
	)
}

// WaitFor polls the desktop until a condition is met or a timeout elapses.
func WaitFor() inventory.ServerTool {
	return NewToolFromHandler(
		ToolsetInteraction,
		mcp.Tool{
			Name: "WaitFor",
			Description: "Poll the desktop until a condition holds or a timeout elapses. Conditions: " +
				"text_exists (the UI tree contains 'text'), active_window (the foreground window title contains 'window_name'), " +
				"element_exists (an interactive element's name contains 'text').",
			Annotations: &mcp.ToolAnnotations{Title: "Wait for condition", ReadOnlyHint: true},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"condition":   {Type: "string", Enum: []any{"text_exists", "active_window", "element_exists"}, Description: "Condition to wait for."},
					"text":        {Type: "string", Description: "Text to look for (text_exists/element_exists)."},
					"window_name": {Type: "string", Description: "Window title substring (active_window)."},
					"timeout":     {Type: "integer", Description: "Max seconds to wait (default 10, max 120)."},
				},
				Required: []string{"condition"},
			},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			condition, err := OptionalStringEnum(args, "condition", "", "text_exists", "active_window", "element_exists")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			text := OptionalString(args, "text", "")
			windowName := OptionalString(args, "window_name", "")
			timeoutSec, err := OptionalInt(args, "timeout", 10)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			if timeoutSec > 120 {
				timeoutSec = 120
			}
			if timeoutSec < 1 {
				timeoutSec = 1
			}

			deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
			for {
				state, err := deps.Desktop().Snapshot(desktop.SnapshotOptions{})
				if err == nil && conditionMet(condition, state, text, windowName) {
					return NewToolResultTextf("Condition %q met.", condition), nil
				}
				if time.Now().After(deadline) {
					return NewToolResultErrorf("timed out after %ds waiting for %q", timeoutSec, condition), nil
				}
				select {
				case <-ctx.Done():
					return NewToolResultError("wait cancelled"), nil
				case <-time.After(400 * time.Millisecond):
				}
			}
		},
	)
}

func conditionMet(condition string, state *desktop.DesktopState, text, windowName string) bool {
	switch condition {
	case "text_exists":
		return text != "" && strings.Contains(state.TreeText, text)
	case "active_window":
		return windowName != "" && strings.Contains(strings.ToLower(state.Foreground.Title), strings.ToLower(windowName))
	case "element_exists":
		for _, e := range state.Interactive {
			if text != "" && strings.Contains(e.Info.Name, text) {
				return true
			}
		}
	}
	return false
}
