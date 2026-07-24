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

// Assert checks a UI condition and returns an explicit PASS/FAIL result, for use
// as a test assertion. A failed assertion is returned as a tool error so the
// agent treats it as a test failure.
func Assert() inventory.ServerTool {
	return NewToolFromHandler(
		ToolsetTesting,
		mcp.Tool{
			Name: "Assert",
			Description: "Assert a UI condition for a test and return PASS or FAIL. Conditions: " +
				"text_present (the UI tree contains 'text'), text_absent (it does not), " +
				"element_present (an interactive element's name contains 'text'), " +
				"window_active (the foreground window title contains 'window_name'). " +
				"A failed assertion is reported as an error.",
			Annotations: &mcp.ToolAnnotations{Title: "Assert UI condition", ReadOnlyHint: true},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"condition":   {Type: "string", Enum: []any{"text_present", "text_absent", "element_present", "window_active"}, Description: "The assertion."},
					"text":        {Type: "string", Description: "Text to check (text_present/text_absent/element_present)."},
					"window_name": {Type: "string", Description: "Window title substring (window_active)."},
					"message":     {Type: "string", Description: "Optional description of what is being verified."},
				},
				Required: []string{"condition"},
			},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			condition, err := OptionalStringEnum(args, "condition", "", "text_present", "text_absent", "element_present", "window_active")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			text := OptionalString(args, "text", "")
			windowName := OptionalString(args, "window_name", "")
			message := OptionalString(args, "message", condition)

			state, err := deps.Desktop().Snapshot(desktop.SnapshotOptions{})
			if err != nil {
				return NewToolResultErrorFromErr("assert: snapshot failed", err), nil
			}

			pass := evalAssertion(condition, state, text, windowName)
			if pass {
				return NewToolResultTextf("PASS: %s", message), nil
			}
			return NewToolResultErrorf("FAIL: %s (condition %q not satisfied)", message, condition), nil
		},
	)
}

func evalAssertion(condition string, state *desktop.DesktopState, text, windowName string) bool {
	switch condition {
	case "text_present":
		return text != "" && strings.Contains(state.TreeText, text)
	case "text_absent":
		return text != "" && !strings.Contains(state.TreeText, text)
	case "element_present":
		for _, e := range state.Interactive {
			if text != "" && strings.Contains(e.Info.Name, text) {
				return true
			}
		}
		return false
	case "window_active":
		return windowName != "" && strings.Contains(strings.ToLower(state.Foreground.Title), strings.ToLower(windowName))
	}
	return false
}

// CaptureEvidence captures a screenshot and the UI-tree snapshot together, for
// test evidence and debugging.
func CaptureEvidence() inventory.ServerTool {
	return NewToolFromHandler(
		ToolsetTesting,
		mcp.Tool{
			Name:        "CaptureEvidence",
			Description: "Capture test evidence in one call: a screenshot image plus the labeled UI-tree snapshot text. Use at key test steps and on failure. Read-only.",
			Annotations: &mcp.ToolAnnotations{Title: "Capture test evidence", ReadOnlyHint: true},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"label": {Type: "string", Description: "Optional caption identifying this evidence (e.g. the test step)."},
				},
			},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			label := OptionalString(args, "label", "")
			dsk := deps.Desktop()

			state, err := dsk.Snapshot(desktop.SnapshotOptions{})
			if err != nil {
				return NewToolResultErrorFromErr("evidence: snapshot failed", err), nil
			}
			pngData, w, h, denom, err := dsk.Screenshot()
			if err != nil {
				return NewToolResultErrorFromErr("evidence: screenshot failed", err), nil
			}

			var caption strings.Builder
			if label != "" {
				fmt.Fprintf(&caption, "Evidence: %s\n", label)
			}
			fmt.Fprintf(&caption, "Screenshot %dx%d", w, h)
			if denom > 1 {
				fmt.Fprintf(&caption, " (downscaled %dx)", denom)
			}
			caption.WriteString("\n\n")
			caption.WriteString(formatSnapshot(state))

			return NewToolResultImage(caption.String(), pngData, "image/png"), nil
		},
	)
}
