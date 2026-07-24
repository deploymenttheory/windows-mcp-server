//go:build windows && (amd64 || arm64)

package windows

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/internal/desktop"
	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

// Snapshot captures the desktop UI state — foreground window, open windows, and
// a labeled tree of interactive elements — for perception and label-based
// interaction. It is read-only.
func Snapshot() inventory.ServerTool {
	return NewToolFromHandler(
		ToolsetScreen,
		mcp.Tool{
			Name:        "Snapshot",
			Description: "Capture the desktop UI state: the foreground window, the list of open windows, and a labeled tree of interactive elements (each shown as [label] ControlType \"Name\" (x,y)). Use an element's label with Click, Type, and Scroll. Read-only; take a fresh Snapshot after the UI changes.",
			Annotations: &mcp.ToolAnnotations{
				Title:        "Snapshot desktop UI",
				ReadOnlyHint: true,
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"all_windows": {
						Type:        "boolean",
						Description: "Walk every visible window's UI tree, not just the foreground window (slower).",
					},
				},
			},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			allWindows := OptionalBool(args, "all_windows", false)

			state, err := deps.Desktop().Snapshot(desktop.SnapshotOptions{AllWindows: allWindows})
			if err != nil {
				return NewToolResultErrorFromErr("failed to capture snapshot", err), nil
			}
			return NewToolResultText(formatSnapshot(state)), nil
		},
	)
}

// formatSnapshot renders a DesktopState as the tool's text output.
func formatSnapshot(state *desktop.DesktopState) string {
	var b strings.Builder

	if state.Foreground.Title != "" {
		fmt.Fprintf(&b, "Foreground window: %q [pid %d]\n\n", state.Foreground.Title, state.Foreground.ProcessID)
	} else {
		b.WriteString("Foreground window: (none)\n\n")
	}

	fmt.Fprintf(&b, "Open windows (%d):\n", len(state.Windows))
	for _, w := range state.Windows {
		marker := ""
		if w.IsForeground {
			marker = " *focused*"
		}
		if w.Minimized {
			marker += " (minimized)"
		}
		fmt.Fprintf(&b, "  - %q [pid %d]%s\n", w.Title, w.ProcessID, marker)
	}

	fmt.Fprintf(&b, "\nInteractive elements: %d (use the [label] with Click/Type/Scroll)\n", len(state.Interactive))
	if hint := accessibilityHint(state.TreeText); hint != "" {
		b.WriteString(hint + "\n")
	}
	b.WriteString("\nUI tree:\n")
	if state.TreeText == "" {
		b.WriteString("(no elements captured)")
	} else {
		b.WriteString(state.TreeText)
	}
	return b.String()
}

// accessibilityHint detects apps (notably VS Code / Electron editors) that gate
// their accessibility tree behind a setting, so the agent understands why the
// content is sparse and how to proceed.
func accessibilityHint(treeText string) string {
	lower := strings.ToLower(treeText)
	if strings.Contains(lower, "not accessible at this time") || strings.Contains(lower, "screen reader optimized") {
		return "Note: the focused app exposes only limited accessibility (an Electron/VS Code editor with " +
			"screen-reader mode off). Its inner content is not in the tree; use Screenshot for vision, or the " +
			"app's own accessibility setting to expose more."
	}
	return ""
}
