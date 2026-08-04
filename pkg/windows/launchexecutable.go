//go:build windows && (amd64 || arm64)

package windows

import (
	"context"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

// LaunchExecutable starts a program by full path.
//
// It lives in ToolsetShell rather than ToolsetApps because it is arbitrary code
// execution, not window management. As a mode of App it shipped in a Default:
// true toolset carried by every persona — including business-user, whose
// instructions promise "no shell, registry, or file-system access" — so a surface
// documented as having no shell could start cmd.exe. Three properties made it
// worse than a plain launch: the path may be UNC, which executes from another host
// outside the egress proxy; cwd is caller-supplied, so pointing a legitimate
// signed binary at an attacker-writable directory is a DLL-search-order hijack;
// and neither is visible in the tool name a reviewer reads.
//
// Grouping it with PowerShell means one decision — "may this persona execute
// arbitrary code?" — instead of two that look unrelated.
func LaunchExecutable() inventory.ServerTool {
	destructive, openWorld := true, true
	return NewToolFromHandler(
		ToolsetShell,
		mcp.Tool{
			Name: "LaunchExecutable",
			Description: "Start a program by full path, with optional arguments and working directory. " +
				"This is arbitrary code execution: prefer App mode=launch for ordinary applications.",
			Annotations: &mcp.ToolAnnotations{
				Title:           "Launch executable",
				ReadOnlyHint:    false,
				DestructiveHint: &destructive,
				OpenWorldHint:   &openWorld,
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"executable": {Type: "string", Description: "Full path to the executable."},
					"args":       {Type: "array", Description: "Arguments.", Items: &jsonschema.Schema{Type: "string"}},
					"cwd":        {Type: "string", Description: "Working directory."},
				},
				Required: []string{"executable"},
			},
		},
		func(_ context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			exe, err := RequiredString(args, "executable")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			var argList []string
			if raw, ok := args["args"].([]any); ok {
				for _, a := range raw {
					if s, ok := a.(string); ok {
						argList = append(argList, s)
					}
				}
			}
			pid, err := deps.Desktop().LaunchExecutable(exe, argList, OptionalString(args, "cwd", ""))
			if err != nil {
				return NewToolResultErrorFromErr("launch failed", err), nil
			}
			return NewToolResultTextf("Started %q (pid %d).", exe, pid), nil
		},
	)
}
