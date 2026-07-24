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

// SystemInfo reports OS and hardware inventory (via WMI) for troubleshooting.
func SystemInfo() inventory.ServerTool {
	return NewToolFromHandler(
		ToolsetDiagnostics,
		mcp.Tool{
			Name:        "SystemInfo",
			Description: "Report OS, hardware, memory, and disk inventory (via WMI). Read-only; useful as the first step in a support diagnosis.",
			Annotations: &mcp.ToolAnnotations{Title: "System information", ReadOnlyHint: true},
			InputSchema: &jsonschema.Schema{Type: "object"},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			si, err := deps.Desktop().GetSystemInfo()
			if err != nil {
				return NewToolResultErrorFromErr("failed to gather system info", err), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "Host:      %s\n", si.Hostname)
			fmt.Fprintf(&b, "OS:        %s (version %s, build %s, %s)\n", si.OSCaption, si.OSVersion, si.BuildNumber, si.OSArch)
			fmt.Fprintf(&b, "Machine:   %s %s\n", si.Manufacturer, si.Model)
			fmt.Fprintf(&b, "CPU:       %s (%d cores / %d logical)\n", si.CPUName, si.PhysicalCores, si.LogicalCPUs)
			fmt.Fprintf(&b, "Memory:    %d MB free of %d MB\n", si.FreeMemoryMB, si.TotalMemoryMB)
			fmt.Fprintf(&b, "Last boot: %s\n", si.LastBoot)
			if len(si.Disks) > 0 {
				b.WriteString("Disks:\n")
				for _, dk := range si.Disks {
					fmt.Fprintf(&b, "  %s %s — %.1f GB free of %.1f GB (%d%% used)\n",
						dk.Drive, dk.Volume, dk.FreeGB, dk.SizeGB, dk.UsedPct)
				}
			}
			return NewToolResultText(b.String()), nil
		},
	)
}

// Service lists or controls Windows services (via WMI).
func Service() inventory.ServerTool {
	destructive := true
	return NewToolFromHandler(
		ToolsetDiagnostics,
		mcp.Tool{
			Name:        "Service",
			Description: "List or control Windows services. mode=list shows services (optionally filtered by name); mode=start/stop/restart controls a service by exact name.",
			Annotations: &mcp.ToolAnnotations{
				Title:           "Windows service control",
				ReadOnlyHint:    false,
				DestructiveHint: &destructive,
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"mode": {Type: "string", Enum: []any{"list", "start", "stop", "restart"}, Description: "Operation."},
					"name": {Type: "string", Description: "Service name (exact for control; substring filter for list)."},
				},
				Required: []string{"mode"},
			},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			mode, err := OptionalStringEnum(args, "mode", "", "list", "start", "stop", "restart")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			dsk := deps.Desktop()

			if mode == "list" {
				services, err := dsk.ListServices(OptionalString(args, "name", ""))
				if err != nil {
					return NewToolResultErrorFromErr("failed to list services", err), nil
				}
				var b strings.Builder
				fmt.Fprintf(&b, "%-32s %-10s %-12s %s\n", "Name", "State", "StartMode", "DisplayName")
				for _, s := range services {
					fmt.Fprintf(&b, "%-32s %-10s %-12s %s\n", truncate(s.Name, 32), s.State, s.StartMode, truncate(s.DisplayName, 48))
				}
				fmt.Fprintf(&b, "\n%d service(s).", len(services))
				return NewToolResultText(b.String()), nil
			}

			name, err := RequiredString(args, "name")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			result, err := dsk.ControlService(name, mode)
			if err != nil {
				return NewToolResultErrorFromErr("service control failed", err), nil
			}
			return NewToolResultText(result), nil
		},
	)
}
