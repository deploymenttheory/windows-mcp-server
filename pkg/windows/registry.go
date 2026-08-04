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

			// Every model-supplied value is bound as data via PSScript rather than
			// interpolated, so a registry path or value cannot break out of its
			// cmdlet argument into a statement. See psscript.go.
			var ps PSScript
			var command string
			switch mode {
			case "get":
				if name == "" {
					return NewToolResultError("name is required for get"), nil
				}
				command = ps.Script("Get-ItemPropertyValue -Path " + ps.Arg(path) + " -Name " + ps.Arg(name))
			case "list":
				command = ps.Script("Get-ItemProperty -Path " + ps.Arg(path) + " | Format-List")
			case "set":
				if name == "" {
					return NewToolResultError("name is required for set"), nil
				}
				valType, err := OptionalStringEnum(args, "type", "String", "String", "DWord", "QWord", "Binary", "ExpandString", "MultiString")
				if err != nil {
					return NewToolResultError(err.Error()), nil
				}
				value := OptionalString(args, "value", "")
				pathRef, nameRef, valueRef := ps.Arg(path), ps.Arg(name), ps.Arg(value)
				command = ps.Script(
					"if (-not (Test-Path " + pathRef + ")) { New-Item -Path " + pathRef + " -Force | Out-Null }; " +
						"New-ItemProperty -Path " + pathRef + " -Name " + nameRef +
						" -Value " + valueRef + " -PropertyType " + valType + " -Force | Out-Null; 'OK'")
			case "delete":
				if name == "" {
					return NewToolResultError("name is required for delete"), nil
				}
				command = ps.Script("Remove-ItemProperty -Path " + ps.Arg(path) + " -Name " + ps.Arg(name) + "; 'OK'")
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
