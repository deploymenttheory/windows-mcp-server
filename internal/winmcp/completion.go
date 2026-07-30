//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
	"github.com/deploymenttheory/windows-mcp-server/pkg/windows"
)

// maxCompletions bounds a completion response. The spec allows the server to
// truncate and report HasMore, which keeps a large tool manifest from dominating
// a completion payload.
const maxCompletions = 100

// completionHandler serves completion/complete for prompt arguments.
//
// Values come only from data the server already holds — persona IDs, toolset IDs,
// tool names, common application names, and configured credential *names*. It
// never sources a credential secret: the Credentials tool's never-read invariant
// applies here too, and a completion response goes straight into the model's
// context.
//
// The SDK validates that Ref and Argument.Name are present before dispatch, so
// this handler can assume both.
func completionHandler(inv *inventory.Inventory) func(context.Context, *mcp.CompleteRequest) (*mcp.CompleteResult, error) {
	return func(ctx context.Context, req *mcp.CompleteRequest) (*mcp.CompleteResult, error) {
		var values []string

		// Only prompt arguments are completed; resource-URI completion would imply
		// enumerating live desktop state, which belongs behind a tool call.
		if req.Params.Ref != nil && req.Params.Ref.Type == "ref/prompt" {
			values = completionValues(ctx, inv, req.Params.Argument.Name)
		}

		values = filterByPrefix(values, req.Params.Argument.Value)
		total := len(values)
		hasMore := false
		if total > maxCompletions {
			values, hasMore = values[:maxCompletions], true
		}

		return &mcp.CompleteResult{
			Completion: mcp.CompletionResultDetails{
				Values:  values,
				Total:   total,
				HasMore: hasMore,
			},
		}, nil
	}
}

// commonApps are frequently automated Windows applications, offered as launch
// suggestions. Deliberately a short curated list rather than an enumeration of
// installed software, which would be slow and leak the machine's inventory.
var commonApps = []string{
	"chrome", "explorer", "msedge", "mspaint", "notepad",
	"outlook", "powershell", "taskmgr", "winword", "wt",
}

// completionValues resolves the candidate set for a prompt argument name.
func completionValues(ctx context.Context, inv *inventory.Inventory, argument string) []string {
	switch strings.ToLower(argument) {
	case "persona":
		out := make([]string, 0, len(windows.Personas))
		for id := range windows.Personas {
			out = append(out, id)
		}
		slices.Sort(out)
		return out

	case "toolset", "toolsets":
		ids := inv.ToolsetIDs()
		out := make([]string, 0, len(ids))
		for _, id := range ids {
			out = append(out, string(id))
		}
		slices.Sort(out)
		return out

	case "tool":
		tools := inv.AvailableTools(ctx)
		out := make([]string, 0, len(tools))
		for i := range tools {
			out = append(out, tools[i].Tool.Name)
		}
		slices.Sort(out)
		return out

	case "app", "application":
		return slices.Clone(commonApps)

	case "credential":
		// Names only — never a target's secret. DepsFromContext rather than the
		// Must variant: completion must degrade quietly if deps are absent.
		deps, ok := windows.DepsFromContext(ctx)
		if !ok {
			return nil
		}
		creds := deps.Credentials()
		out := make([]string, 0, len(creds))
		for _, c := range creds {
			out = append(out, c.Name)
		}
		slices.Sort(out)
		return out
	}
	return nil
}

// filterByPrefix narrows candidates to those matching what has been typed,
// case-insensitively.
func filterByPrefix(values []string, typed string) []string {
	if typed == "" {
		return values
	}
	lower := strings.ToLower(typed)
	out := values[:0:0]
	for _, v := range values {
		if strings.HasPrefix(strings.ToLower(v), lower) {
			out = append(out, v)
		}
	}
	return out
}
