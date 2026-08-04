//go:build windows && (amd64 || arm64)

package windows

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

// packageTimeout bounds an install/uninstall: they download and run installers,
// which can take minutes, so the window is far longer than a query's.
const packageTimeout = 10 * time.Minute

// Package installs, removes, lists, and searches software via winget and MSI.
//
// It is destructive and open-world: install and uninstall change what is on the
// machine, and both winget and an MSI download from the network — outside the
// egress proxy — so the tool is annotated open-world and lives in an opt-in
// toolset that no persona carries.
func Package() inventory.ServerTool {
	destructive := true
	openWorld := true
	return NewToolFromHandler(
		ToolsetPackages,
		mcp.Tool{
			Name: "Package",
			Description: "Install, remove, list, and search software. mode=list shows installed packages; " +
				"mode=search finds packages by query; mode=install installs a winget package by id (or a local " +
				".msi by path); mode=uninstall removes a winget package by id. Installs download from the " +
				"network, outside the egress proxy.",
			Annotations: &mcp.ToolAnnotations{
				Title:           "Software package management",
				ReadOnlyHint:    false,
				DestructiveHint: &destructive,
				OpenWorldHint:   &openWorld,
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"mode":  {Type: "string", Enum: []any{"list", "search", "install", "uninstall"}, Description: "Operation."},
					"query": {Type: "string", Description: "Search term (mode=search)."},
					"id":    {Type: "string", Description: "Exact winget package id (mode=install/uninstall)."},
					"msi":   {Type: "string", Description: "Path to a local .msi to install (mode=install; an alternative to id)."},
				},
				Required: []string{"mode"},
			},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			mode, err := OptionalStringEnum(args, "mode", "", "list", "search", "install", "uninstall")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}

			command, timeout, err := packageCommand(mode, args)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}

			res, err := deps.Desktop().RunPowerShell(ctx, command, timeout)
			if err != nil {
				return NewToolResultErrorFromErr("package command failed", err), nil
			}
			out := strings.TrimSpace(res.Output)
			if res.TimedOut {
				return NewToolResultErrorf("package command timed out"), nil
			}
			if res.ExitCode != 0 {
				return NewToolResultErrorf("package command failed (exit %d): %s", res.ExitCode, out), nil
			}
			if out == "" {
				return NewToolResultText("OK"), nil
			}
			return NewToolResultText(out), nil
		},
	)
}

// wingetNonInteractive are the flags that keep winget from prompting or blocking
// on an agreement — required when no human is at the console.
const wingetNonInteractive = "--accept-source-agreements --accept-package-agreements --disable-interactivity"

// packageCommand builds the command and its timeout for one mode. Every
// caller-supplied value is bound as data via PSScript rather than interpolated,
// so a package id or path cannot break out into a statement. See psscript.go.
func packageCommand(mode string, args map[string]any) (string, time.Duration, error) {
	var ps PSScript
	switch mode {
	case "list":
		return "winget list --disable-interactivity", 60 * time.Second, nil
	case "search":
		query, err := RequiredString(args, "query")
		if err != nil {
			return "", 0, err
		}
		return ps.Script("winget search --query " + ps.Arg(query) + " " + wingetNonInteractive), 60 * time.Second, nil
	case "install":
		// A local MSI is an alternative to a winget id; if given, it takes precedence.
		if msi := OptionalString(args, "msi", ""); msi != "" {
			if !strings.HasSuffix(strings.ToLower(msi), ".msi") {
				return "", 0, fmt.Errorf("msi must be a path to a .msi file")
			}
			// Start-Process waits, and $LASTEXITCODE is not set by msiexec through
			// Start-Process, so surface the process exit code explicitly.
			return ps.Script("$p = Start-Process msiexec.exe -ArgumentList '/i', " + ps.Arg(msi) +
				", '/quiet', '/norestart' -Wait -PassThru; " +
				"if ($p.ExitCode -ne 0) { throw \"msiexec exit $($p.ExitCode)\" }; 'installed'"), packageTimeout, nil
		}
		id, err := RequiredString(args, "id")
		if err != nil {
			return "", 0, err
		}
		return ps.Script("winget install --id " + ps.Arg(id) + " --exact " + wingetNonInteractive), packageTimeout, nil
	case "uninstall":
		id, err := RequiredString(args, "id")
		if err != nil {
			return "", 0, err
		}
		return ps.Script("winget uninstall --id " + ps.Arg(id) + " --exact " + wingetNonInteractive), packageTimeout, nil
	default:
		return "", 0, fmt.Errorf("unknown mode %q", mode)
	}
}
