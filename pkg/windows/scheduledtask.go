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

// ScheduledTask lists, inspects, and manages Windows scheduled tasks via the
// ScheduledTasks PowerShell module.
//
// The tool is annotated destructive as a whole: list and get read, but create,
// delete, enable, disable and run all change the machine's scheduled work, and a
// policy rule matching the destructive annotation should cover every mode.
func ScheduledTask() inventory.ServerTool {
	destructive := true
	return NewToolFromHandler(
		ToolsetSystem,
		mcp.Tool{
			Name: "ScheduledTask",
			Description: "List, inspect, and manage Windows scheduled tasks. mode=list shows tasks (optionally " +
				"filtered by name); mode=get shows one task's schedule and last-run details; mode=run/enable/" +
				"disable/delete control a task by exact name; mode=create registers a task that runs a program " +
				"on a trigger (at_logon, at_startup, daily, or once).",
			Annotations: &mcp.ToolAnnotations{
				Title:           "Scheduled task management",
				ReadOnlyHint:    false,
				DestructiveHint: &destructive,
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"mode":      {Type: "string", Enum: []any{"list", "get", "run", "enable", "disable", "delete", "create"}, Description: "Operation."},
					"name":      {Type: "string", Description: "Task name (exact for get/control/create; substring filter for list)."},
					"action":    {Type: "string", Description: "Program or script to run (mode=create)."},
					"arguments": {Type: "string", Description: "Arguments passed to the action (mode=create)."},
					"trigger":   {Type: "string", Enum: []any{"at_logon", "at_startup", "daily", "once"}, Description: "When the task fires (mode=create)."},
					"time":      {Type: "string", Description: "Time of day HH:mm for the daily/once triggers (mode=create; default 09:00)."},
					"description": {Type: "string", Description: "Optional description (mode=create)."},
				},
				Required: []string{"mode"},
			},
		},
		func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := ArgsMap(req)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}
			mode, err := OptionalStringEnum(args, "mode", "", "list", "get", "run", "enable", "disable", "delete", "create")
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}

			command, err := scheduledTaskCommand(mode, args)
			if err != nil {
				return NewToolResultError(err.Error()), nil
			}

			res, err := deps.Desktop().RunPowerShell(ctx, command, 60*time.Second)
			if err != nil {
				return NewToolResultErrorFromErr("scheduled task command failed", err), nil
			}
			out := strings.TrimSpace(res.Output)
			if res.TimedOut {
				return NewToolResultErrorf("scheduled task command timed out"), nil
			}
			if res.ExitCode != 0 {
				return NewToolResultErrorf("scheduled task command failed: %s", out), nil
			}
			if out == "" {
				return NewToolResultText("OK"), nil
			}
			return NewToolResultText(out), nil
		},
	)
}

// scheduledTaskCommand builds the PowerShell for one mode. Every caller-supplied
// value is bound as data via PSScript rather than interpolated, so a task name or
// action cannot break out of its cmdlet argument into a statement. See
// psscript.go.
func scheduledTaskCommand(mode string, args map[string]any) (string, error) {
	var ps PSScript
	if mode == "list" {
		filter := OptionalString(args, "name", "")
		sel := "Get-ScheduledTask"
		if filter != "" {
			sel += " -TaskName ('*' + " + ps.Arg(filter) + " + '*')"
		}
		return ps.Script("$ErrorActionPreference='Stop'; " + sel +
			" | Select-Object TaskName, TaskPath, State | ConvertTo-Json -Depth 3 -AsArray"), nil
	}

	name, err := RequiredString(args, "name")
	if err != nil {
		return "", err
	}
	q := ps.Arg(name)

	switch mode {
	case "get":
		return ps.Script("$ErrorActionPreference='Stop'; $t = Get-ScheduledTask -TaskName " + q + "; " +
			"$i = $t | Get-ScheduledTaskInfo; " +
			"[pscustomobject]@{ TaskName=$t.TaskName; TaskPath=$t.TaskPath; State=$t.State.ToString(); " +
			"LastRunTime=$i.LastRunTime; NextRunTime=$i.NextRunTime; LastTaskResult=$i.LastTaskResult } | " +
			"ConvertTo-Json -Depth 3"), nil
	case "run":
		return ps.Script("$ErrorActionPreference='Stop'; Start-ScheduledTask -TaskName " + q + "; 'started'"), nil
	case "enable":
		return ps.Script("$ErrorActionPreference='Stop'; Enable-ScheduledTask -TaskName " + q + " | Out-Null; 'enabled'"), nil
	case "disable":
		return ps.Script("$ErrorActionPreference='Stop'; Disable-ScheduledTask -TaskName " + q + " | Out-Null; 'disabled'"), nil
	case "delete":
		return ps.Script("$ErrorActionPreference='Stop'; Unregister-ScheduledTask -TaskName " + q +
			" -Confirm:$false; 'deleted'"), nil
	case "create":
		return scheduledTaskCreateCommand(&ps, q, args)
	default:
		return "", fmt.Errorf("unknown mode %q", mode)
	}
}

// scheduledTaskCreateCommand builds a Register-ScheduledTask invocation for a task
// that runs a program on a trigger. It shares the caller's PSScript so every value
// is bound as data in one script.
func scheduledTaskCreateCommand(ps *PSScript, nameRef string, args map[string]any) (string, error) {
	action, err := RequiredString(args, "action")
	if err != nil {
		return "", err
	}
	trigger, err := OptionalStringEnum(args, "trigger", "", "at_logon", "at_startup", "daily", "once")
	if err != nil {
		return "", err
	}
	if trigger == "" {
		return "", fmt.Errorf("create requires a trigger (at_logon, at_startup, daily, or once)")
	}

	act := "$a = New-ScheduledTaskAction -Execute " + ps.Arg(action)
	if arguments := OptionalString(args, "arguments", ""); arguments != "" {
		act += " -Argument " + ps.Arg(arguments)
	}

	var trig string
	switch trigger {
	case "at_logon":
		trig = "$t = New-ScheduledTaskTrigger -AtLogOn"
	case "at_startup":
		trig = "$t = New-ScheduledTaskTrigger -AtStartup"
	case "daily":
		trig = "$t = New-ScheduledTaskTrigger -Daily -At " + ps.Arg(OptionalString(args, "time", "09:00"))
	case "once":
		trig = "$t = New-ScheduledTaskTrigger -Once -At " + ps.Arg(OptionalString(args, "time", "09:00"))
	}

	register := "Register-ScheduledTask -TaskName " + nameRef + " -Action $a -Trigger $t -Force"
	if desc := OptionalString(args, "description", ""); desc != "" {
		register += " -Description " + ps.Arg(desc)
	}
	register += " | Out-Null; 'created'"

	return ps.Script("$ErrorActionPreference='Stop'; " + act + "; " + trig + "; " + register), nil
}
