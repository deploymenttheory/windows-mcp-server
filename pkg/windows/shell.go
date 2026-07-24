//go:build windows && (amd64 || arm64)

package windows

import (
	"context"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

// PowerShell executes an arbitrary PowerShell command. It is powerful and
// potentially destructive, so it lives in the non-default 'shell' toolset.
func PowerShell() inventory.ServerTool {
	destructive := true
	openWorld := true
	return NewToolFromHandler(
		ToolsetShell,
		mcp.Tool{
			Name:        "PowerShell",
			Description: "Execute a PowerShell command and return its combined output and exit code. Prefers PowerShell 7 (pwsh), falling back to Windows PowerShell 5.1. Has full system access.",
			Annotations: &mcp.ToolAnnotations{
				Title:           "Run PowerShell command",
				ReadOnlyHint:    false,
				DestructiveHint: &destructive,
				OpenWorldHint:   &openWorld,
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"command": {
						Type:        "string",
						Description: "The PowerShell command to execute.",
					},
					"timeout": {
						Type:        "integer",
						Description: "Timeout in seconds (default 30, clamped to 1-600).",
					},
				},
				Required: []string{"command"},
			},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			command, err := RequiredString(args, "command")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			timeoutSec, err := OptionalInt(args, "timeout", 30)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			if timeoutSec < 1 {
				timeoutSec = 1
			}
			if timeoutSec > 600 {
				timeoutSec = 600
			}

			res, err := deps.Desktop().RunPowerShell(ctx, command, time.Duration(timeoutSec)*time.Second)
			if err != nil {
				return NewToolResultErrorFromErr("failed to run PowerShell", err), nil
			}
			if res.TimedOut {
				return NewToolResultErrorf("Command timed out after %d second(s).\nPartial output:\n%s", timeoutSec, res.Output), nil
			}

			result := NewToolResultTextf("Exit code: %d\n%s", res.ExitCode, res.Output)
			if res.ExitCode != 0 {
				result.IsError = true
			}
			return result, nil
		},
	)
}
