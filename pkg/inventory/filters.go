package inventory

import (
	"context"
	"fmt"
	"os"
	"slices"
	"sort"
)

// FeatureFlagChecker reports whether a feature flag is enabled. The context may
// carry actor/request information used to evaluate the flag. On error the
// caller logs and treats the flag as disabled.
type FeatureFlagChecker func(ctx context.Context, flagName string) (bool, error)

// featureFlagAllowed reports whether an item with the given enable/disable flag
// pair is permitted under the supplied checker (which must be non-nil).
//
//   - If enableFlag is set, the item is allowed only if that flag is enabled.
//   - If any disableFlag is enabled, the item is excluded.
//
// A checker error is logged and treated as "flag not enabled": an enable-flag
// error excludes the item, a disable-flag error keeps it.
func featureFlagAllowed(ctx context.Context, checker FeatureFlagChecker, enableFlag string, disableFlags []string) bool {
	check := func(flag string) bool {
		enabled, err := checker(ctx, flag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "inventory: feature flag check error for %q: %v\n", flag, err)
			return false
		}
		return enabled
	}
	if enableFlag != "" && !check(enableFlag) {
		return false
	}
	return !slices.ContainsFunc(disableFlags, check)
}

// createFeatureFlagFilter returns a ToolFilter gating tools on their
// FeatureFlagEnable / FeatureFlagDisable annotations. Builder.Build installs it
// exactly once when a non-nil checker was provided, so "no feature filtering"
// is expressed structurally by the filter's absence.
func createFeatureFlagFilter(checker FeatureFlagChecker) ToolFilter {
	return func(ctx context.Context, tool *ServerTool) (bool, error) {
		return featureFlagAllowed(ctx, checker, tool.FeatureFlagEnable, tool.FeatureFlagDisable), nil
	}
}

// sortByToolsetThenName sorts items by toolset ID, breaking ties by name.
func sortByToolsetThenName[T any](items []T, toolsetID func(T) ToolsetID, name func(T) string) {
	sort.Slice(items, func(i, j int) bool {
		idI, idJ := toolsetID(items[i]), toolsetID(items[j])
		if idI != idJ {
			return idI < idJ
		}
		return name(items[i]) < name(items[j])
	})
}

func sortTools(tools []ServerTool) {
	sortByToolsetThenName(tools,
		func(t ServerTool) ToolsetID { return t.Toolset.ID },
		func(t ServerTool) string { return t.Tool.Name },
	)
}

func sortResourceTemplates(rts []ServerResourceTemplate) {
	sortByToolsetThenName(rts,
		func(r ServerResourceTemplate) ToolsetID { return r.Toolset.ID },
		func(r ServerResourceTemplate) string { return r.Template.Name },
	)
}

func sortPrompts(prompts []ServerPrompt) {
	sortByToolsetThenName(prompts,
		func(p ServerPrompt) ToolsetID { return p.Toolset.ID },
		func(p ServerPrompt) string { return p.Prompt.Name },
	)
}
