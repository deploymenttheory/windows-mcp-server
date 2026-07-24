//go:build windows && (amd64 || arm64)

package windows

import (
	"context"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

// psQuote single-quotes and escapes a string for safe embedding in a PowerShell
// command.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// Registry reads and writes the Windows registry via PowerShell cmdlets.
func Registry() inventory.ServerTool {
	destructive := true
	return NewToolFromHandler(
		ToolsetSystem,
		mcp.Tool{
			Name: "Registry",
			Description: "Read and write the Windows registry. Paths use PowerShell drive syntax, e.g. \"HKCU:\\Software\\MyApp\". " +
				"Modes: get (read a value), set (write a value), delete (remove a value), list (enumerate a key's values).",
			Annotations: &mcp.ToolAnnotations{
				Title:           "Registry get/set/delete/list",
				ReadOnlyHint:    false,
				DestructiveHint: &destructive,
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"mode":  {Type: "string", Enum: []any{"get", "set", "delete", "list"}, Description: "Operation."},
					"path":  {Type: "string", Description: "Registry key path (PowerShell syntax, e.g. HKCU:\\Software\\MyApp)."},
					"name":  {Type: "string", Description: "Value name (get/set/delete)."},
					"value": {Type: "string", Description: "Value data (set)."},
					"type":  {Type: "string", Enum: []any{"String", "DWord", "QWord", "Binary", "ExpandString", "MultiString"}, Description: "Value type for set (default String)."},
				},
				Required: []string{"mode", "path"},
			},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			mode, err := OptionalStringEnum(args, "mode", "", "get", "set", "delete", "list")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			path, err := RequiredString(args, "path")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			name := OptionalString(args, "name", "")

			var command string
			switch mode {
			case "get":
				if name == "" {
					return NewToolResultError("name is required for get"), nil
				}
				command = "Get-ItemPropertyValue -Path " + psQuote(path) + " -Name " + psQuote(name)
			case "list":
				command = "Get-ItemProperty -Path " + psQuote(path) + " | Format-List"
			case "set":
				if name == "" {
					return NewToolResultError("name is required for set"), nil
				}
				valType, err := OptionalStringEnum(args, "type", "String", "String", "DWord", "QWord", "Binary", "ExpandString", "MultiString")
				if err != nil {
					return NewToolResultError(err.Error()), nil
				}
				value := OptionalString(args, "value", "")
				command = "if (-not (Test-Path " + psQuote(path) + ")) { New-Item -Path " + psQuote(path) + " -Force | Out-Null }; " +
					"New-ItemProperty -Path " + psQuote(path) + " -Name " + psQuote(name) +
					" -Value " + psQuote(value) + " -PropertyType " + valType + " -Force | Out-Null; 'OK'"
			case "delete":
				if name == "" {
					return NewToolResultError("name is required for delete"), nil
				}
				command = "Remove-ItemProperty -Path " + psQuote(path) + " -Name " + psQuote(name) + "; 'OK'"
			default:
				return NewToolResultError("invalid mode"), nil
			}

			res, err := deps.Desktop().RunPowerShell(ctx, command, 20*time.Second)
			if err != nil {
				return NewToolResultErrorFromErr("registry operation failed", err), nil
			}
			out := strings.TrimSpace(res.Output)
			if res.ExitCode != 0 {
				return NewToolResultErrorf("registry operation failed (exit %d):\n%s", res.ExitCode, out), nil
			}
			return NewToolResultText(out), nil
		},
	)
}
