//go:build windows && (amd64 || arm64)

package windows

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

// eventLogLevels maps the friendly level names the tool accepts to the numeric
// levels Get-WinEvent's FilterHashtable expects.
var eventLogLevels = map[string]int{
	"critical": 1, "error": 2, "warning": 3, "information": 4, "verbose": 5,
}

// EventLog queries a Windows event log via Get-WinEvent. Read-only: it is the
// natural first step in diagnosing a crash or a failed service.
func EventLog() inventory.ServerTool {
	return NewToolFromHandler(
		ToolsetDiagnostics,
		mcp.Tool{
			Name: "EventLog",
			Description: "Query a Windows event log via Get-WinEvent. Filter by log (default \"System\"), level, " +
				"provider, and a look-back window in hours; returns the most recent matching events as JSON. " +
				"Read-only; the first step in diagnosing a crash or a failed service.",
			Annotations: &mcp.ToolAnnotations{Title: "Query Windows event log", ReadOnlyHint: true},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"log":      {Type: "string", Description: "Log name, e.g. System, Application, Security. Default System."},
					"level":    {Type: "string", Enum: []any{"critical", "error", "warning", "information", "verbose"}, Description: "Only events at this level."},
					"provider": {Type: "string", Description: "Only events from this provider (source)."},
					"hours":    {Type: "integer", Description: "Look back this many hours (default 24, max 720)."},
					"max":      {Type: "integer", Description: "Maximum events to return (default 50, max 500)."},
				},
			},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			log := OptionalString(args, "log", "System")
			level, err := OptionalStringEnum(args, "level", "", "critical", "error", "warning", "information", "verbose")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			provider := OptionalString(args, "provider", "")
			hoursArg, err := OptionalInt(args, "hours", 24)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			maxArg, err := OptionalInt(args, "max", 50)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			hours := clampInt(hoursArg, 1, 720)
			max := clampInt(maxArg, 1, 500)

			// Build the FilterHashtable from vetted parts. Model-supplied strings are
			// bound as data via PSScript, so a log or provider name cannot break out
			// of the hashtable into a statement. See psscript.go.
			var ps PSScript
			filter := "LogName=" + ps.Arg(log)
			if n, ok := eventLogLevels[level]; ok {
				filter += "; Level=" + strconv.Itoa(n)
			}
			if provider != "" {
				filter += "; ProviderName=" + ps.Arg(provider)
			}
			filter += fmt.Sprintf("; StartTime=(Get-Date).AddHours(-%d)", hours)

			// A FilterHashtable that matches nothing makes Get-WinEvent throw
			// "No events were found"; catch exactly that and return an empty array
			// rather than an error, so "nothing happened" reads as a clean result.
			command := ps.Script("$ErrorActionPreference='Stop'; try { " +
				fmt.Sprintf("Get-WinEvent -FilterHashtable @{ %s } -MaxEvents %d -ErrorAction Stop | ", filter, max) +
				"Select-Object @{n='time';e={$_.TimeCreated.ToString('s')}}, Id, " +
				"@{n='level';e={$_.LevelDisplayName}}, @{n='provider';e={$_.ProviderName}}, " +
				"@{n='message';e={($_.Message -replace '\\s+',' ').Trim()}} | " +
				"ConvertTo-Json -Depth 3 -AsArray } " +
				"catch { if ($_.Exception.Message -match 'No events were found') { '[]' } else { throw } }")

			res, err := deps.Desktop().RunPowerShell(ctx, command, 60*time.Second)
			if err != nil {
				return NewToolResultErrorFromErr("event log query failed", err), nil
			}
			out := strings.TrimSpace(res.Output)
			if res.TimedOut {
				return NewToolResultErrorf("event log query timed out"), nil
			}
			if res.ExitCode != 0 {
				return NewToolResultErrorf("event log query failed: %s", out), nil
			}
			if out == "" || out == "[]" {
				return NewToolResultText("No matching events."), nil
			}
			return NewToolResultText(out), nil
		},
	)
}
