package inventory

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// ErrUnknownTools is returned by Build when tools named via WithTools are not
// recognized.
var ErrUnknownTools = errors.New("unknown tools specified in WithTools")

// ToolFilter decides whether a tool should be included. Returning false (or an
// error) excludes the tool.
type ToolFilter func(ctx context.Context, tool *ServerTool) (bool, error)

// Builder assembles an Inventory. Configure it with the fluent With* methods,
// then call Build.
//
//	inv, err := NewBuilder().
//	    SetTools(AllTools()).
//	    WithReadOnly(true).
//	    WithToolsets([]string{"interaction", "system"}).
//	    Build()
type Builder struct {
	tools             []ServerTool
	resources         []ServerResource
	resourceTemplates []ServerResourceTemplate
	prompts           []ServerPrompt
	deprecatedAliases map[string]string

	readOnly             bool
	toolsetIDs           []string
	toolsetIDsIsNil      bool
	additionalTools      []string
	featureChecker       FeatureFlagChecker
	filters              []ToolFilter
	generateInstructions bool
}

// NewBuilder creates a Builder that defaults to the "default" toolset selection.
func NewBuilder() *Builder {
	return &Builder{
		deprecatedAliases: make(map[string]string),
		toolsetIDsIsNil:   true,
	}
}

// SetTools sets the full tool manifest.
func (b *Builder) SetTools(tools []ServerTool) *Builder {
	b.tools = tools
	return b
}

// SetResources sets the resource template manifest.
func (b *Builder) SetResources(resources []ServerResourceTemplate) *Builder {
	b.resourceTemplates = resources
	return b
}

// SetFixedResources sets the fixed-URI resource manifest.
//
// Separate from SetResources (which takes templates) because the MCP server keeps
// the two in disjoint collections: resources/list paginates only fixed resources.
// Registering templates alone yields an empty resources/list.
func (b *Builder) SetFixedResources(resources []ServerResource) *Builder {
	b.resources = resources
	return b
}

// SetPrompts sets the prompt manifest.
func (b *Builder) SetPrompts(prompts []ServerPrompt) *Builder {
	b.prompts = prompts
	return b
}

// WithDeprecatedAliases registers old→canonical tool name aliases.
func (b *Builder) WithDeprecatedAliases(aliases map[string]string) *Builder {
	maps.Copy(b.deprecatedAliases, aliases)
	return b
}

// WithReadOnly, when true, filters out any tool not annotated read-only.
func (b *Builder) WithReadOnly(readOnly bool) *Builder {
	b.readOnly = readOnly
	return b
}

// WithServerInstructions enables aggregation of per-toolset instructions into
// the Inventory's Instructions string.
func (b *Builder) WithServerInstructions() *Builder {
	b.generateInstructions = true
	return b
}

// WithToolsets selects which toolsets to enable. Special keywords:
//   - "all": enable every toolset
//   - "default": expand to toolsets marked Default
//
// Pass nil to use the default toolsets; pass an empty (non-nil) slice to enable
// none.
func (b *Builder) WithToolsets(toolsetIDs []string) *Builder {
	b.toolsetIDs = toolsetIDs
	b.toolsetIDsIsNil = toolsetIDs == nil
	return b
}

// WithTools names individual tools that bypass toolset filtering (they are
// included even if their toolset is disabled). Read-only and other filters
// still apply.
func (b *Builder) WithTools(toolNames []string) *Builder {
	b.additionalTools = toolNames
	return b
}

// WithFeatureChecker sets the feature-flag checker. When non-nil, Build
// installs a feature-flag filter at the head of the pipeline so tools annotated
// with FeatureFlagEnable/Disable are gated. Resources and prompts use the same
// checker at their iteration sites.
func (b *Builder) WithFeatureChecker(checker FeatureFlagChecker) *Builder {
	b.featureChecker = checker
	return b
}

// WithFilter appends an arbitrary predicate applied to every tool.
func (b *Builder) WithFilter(filter ToolFilter) *Builder {
	b.filters = append(b.filters, filter)
	return b
}

// WithExcludeTools names tools to exclude regardless of other settings. This
// takes precedence over toolset and additional-tool selection.
func (b *Builder) WithExcludeTools(toolNames []string) *Builder {
	cleaned := cleanTools(toolNames)
	if len(cleaned) > 0 {
		b.filters = append(b.filters, createExcludeToolsFilter(cleaned))
	}
	return b
}

func createExcludeToolsFilter(excluded []string) ToolFilter {
	set := make(map[string]struct{}, len(excluded))
	for _, name := range excluded {
		set[name] = struct{}{}
	}
	return func(_ context.Context, tool *ServerTool) (bool, error) {
		_, blocked := set[tool.Tool.Name]
		return !blocked, nil
	}
}

func cleanTools(tools []string) []string {
	seen := make(map[string]bool)
	var cleaned []string
	for _, name := range tools {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" || seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		cleaned = append(cleaned, trimmed)
	}
	return cleaned
}

// Build produces the Inventory. It returns ErrUnknownTools if WithTools names a
// tool that does not exist (and is not a deprecated alias).
func (b *Builder) Build() (*Inventory, error) {
	// Install the feature-flag filter at the head of the pipeline so flag-gated
	// tools are excluded before any user-supplied WithFilter sees them.
	filters := b.filters
	if b.featureChecker != nil {
		filters = append([]ToolFilter{createFeatureFlagFilter(b.featureChecker)}, filters...)
	}

	r := &Inventory{
		tools:             b.tools,
		resources:         b.resources,
		resourceTemplates: b.resourceTemplates,
		prompts:           b.prompts,
		deprecatedAliases: b.deprecatedAliases,
		readOnly:          b.readOnly,
		featureChecker:    b.featureChecker,
		filters:           filters,
	}

	r.enabledToolsets, r.unrecognizedToolsets, r.toolsetIDs, r.toolsetIDSet, r.defaultToolsetIDs, r.toolsetDescriptions = b.processToolsets()

	validToolNames := make(map[string]bool, len(b.tools))
	for i := range b.tools {
		validToolNames[b.tools[i].Tool.Name] = true
	}

	if len(b.additionalTools) > 0 {
		cleaned := cleanTools(b.additionalTools)
		r.additionalTools = make(map[string]bool, len(cleaned))
		var unrecognized []string
		for _, name := range cleaned {
			r.additionalTools[name] = true
			if canonical, isAlias := b.deprecatedAliases[name]; isAlias {
				r.additionalTools[canonical] = true
			} else if !validToolNames[name] {
				unrecognized = append(unrecognized, name)
			}
		}
		if len(unrecognized) > 0 {
			return nil, fmt.Errorf("%w: %s", ErrUnknownTools, strings.Join(unrecognized, ", "))
		}
	}

	if b.generateInstructions {
		r.instructions = generateInstructions(r)
	}

	return r, nil
}

// processToolsets resolves the requested toolset selection against the toolsets
// declared by the tools, resources, and prompts themselves.
func (b *Builder) processToolsets() (
	enabled map[ToolsetID]bool,
	unrecognized []string,
	allIDs []ToolsetID,
	idSet map[ToolsetID]bool,
	defaultIDs []ToolsetID,
	descriptions map[ToolsetID]string,
) {
	validIDs := make(map[ToolsetID]bool)
	defaultIDset := make(map[ToolsetID]bool)
	descriptions = make(map[ToolsetID]string)

	collect := func(ts ToolsetMetadata) {
		validIDs[ts.ID] = true
		if ts.Default {
			defaultIDset[ts.ID] = true
		}
		if ts.Description != "" {
			descriptions[ts.ID] = ts.Description
		}
	}
	for i := range b.tools {
		collect(b.tools[i].Toolset)
	}
	for i := range b.resources {
		collect(b.resources[i].Toolset)
	}
	for i := range b.resourceTemplates {
		collect(b.resourceTemplates[i].Toolset)
	}
	for i := range b.prompts {
		collect(b.prompts[i].Toolset)
	}

	allIDs = make([]ToolsetID, 0, len(validIDs))
	for id := range validIDs {
		allIDs = append(allIDs, id)
	}
	slices.Sort(allIDs)

	defaultIDs = make([]ToolsetID, 0, len(defaultIDset))
	for id := range defaultIDset {
		defaultIDs = append(defaultIDs, id)
	}
	slices.Sort(defaultIDs)

	toolsetIDs := b.toolsetIDs

	for _, id := range toolsetIDs {
		if strings.TrimSpace(id) == "all" {
			// nil enabled map means "all enabled".
			return nil, nil, allIDs, validIDs, defaultIDs, descriptions
		}
	}

	if b.toolsetIDsIsNil {
		toolsetIDs = []string{"default"}
	}

	seen := make(map[ToolsetID]bool)
	expanded := make([]ToolsetID, 0, len(toolsetIDs))
	for _, id := range toolsetIDs {
		trimmed := strings.TrimSpace(id)
		if trimmed == "" {
			continue
		}
		if trimmed == "default" {
			for _, d := range defaultIDs {
				if !seen[d] {
					seen[d] = true
					expanded = append(expanded, d)
				}
			}
			continue
		}
		tsID := ToolsetID(trimmed)
		if !seen[tsID] {
			seen[tsID] = true
			expanded = append(expanded, tsID)
			if !validIDs[tsID] {
				unrecognized = append(unrecognized, trimmed)
			}
		}
	}

	enabled = make(map[ToolsetID]bool, len(expanded))
	for _, id := range expanded {
		enabled[id] = true
	}
	return enabled, unrecognized, allIDs, validIDs, defaultIDs, descriptions
}
