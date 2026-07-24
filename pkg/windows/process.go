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

// Process lists or kills running processes (via WMI).
func Process() inventory.ServerTool {
	destructive := true
	return NewToolFromHandler(
		ToolsetSystem,
		mcp.Tool{
			Name:        "Process",
			Description: "List or kill running processes via WMI. mode=list returns processes sorted by memory/name/pid; mode=kill terminates processes by pid or name substring.",
			Annotations: &mcp.ToolAnnotations{
				Title:           "Process list/kill",
				ReadOnlyHint:    false,
				DestructiveHint: &destructive,
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"mode":    {Type: "string", Enum: []any{"list", "kill"}, Description: "Operation."},
					"name":    {Type: "string", Description: "Process name substring (kill; or filter for list)."},
					"pid":     {Type: "integer", Description: "Process id (kill)."},
					"sort_by": {Type: "string", Enum: []any{"memory", "name", "pid"}, Description: "List sort order (default memory)."},
					"limit":   {Type: "integer", Description: "Max processes to list (default 30)."},
				},
				Required: []string{"mode"},
			},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			mode, err := OptionalStringEnum(args, "mode", "", "list", "kill")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			dsk := deps.Desktop()

			switch mode {
			case "list":
				sortBy, err := OptionalStringEnum(args, "sort_by", "memory", "memory", "name", "pid")
				if err != nil {
					return NewToolResultError(err.Error()), nil
				}
				limit, err := OptionalInt(args, "limit", 30)
				if err != nil {
					return NewToolResultError(err.Error()), nil
				}
				nameFilter := strings.ToLower(OptionalString(args, "name", ""))
				procs, err := dsk.ProcessList(sortBy, 0)
				if err != nil {
					return NewToolResultErrorFromErr("failed to list processes", err), nil
				}
				var b strings.Builder
				fmt.Fprintf(&b, "%-8s %-32s %12s %8s\n", "PID", "Name", "Memory(KB)", "Threads")
				count := 0
				for _, p := range procs {
					if nameFilter != "" && !strings.Contains(strings.ToLower(p.Name), nameFilter) {
						continue
					}
					fmt.Fprintf(&b, "%-8d %-32s %12d %8d\n", p.PID, truncate(p.Name, 32), p.WorkingSetKB, p.ThreadCount)
					count++
					if limit > 0 && count >= limit {
						break
					}
				}
				fmt.Fprintf(&b, "\n%d process(es) shown.", count)
				return NewToolResultText(b.String()), nil

			case "kill":
				pid, err := OptionalInt(args, "pid", 0)
				if err != nil {
					return NewToolResultError(err.Error()), nil
				}
				name := OptionalString(args, "name", "")
				if pid == 0 && name == "" {
					return NewToolResultError("provide 'pid' or 'name' to kill"), nil
				}
				killed, err := dsk.ProcessKill(uint32(pid), name)
				if err != nil {
					return NewToolResultErrorFromErr("failed to kill process", err), nil
				}
				return NewToolResultTextf("Terminated %d process(es).", killed), nil

			default:
				return NewToolResultError("invalid mode"), nil
			}
		},
	)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
