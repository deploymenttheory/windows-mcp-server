package inventory

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Inventory holds a filtered view of tools, resources, and prompts. Build one
// with Builder.
type Inventory struct {
	tools             []ServerTool
	resourceTemplates []ServerResourceTemplate
	prompts           []ServerPrompt
	deprecatedAliases map[string]string

	toolsetIDs          []ToolsetID
	toolsetIDSet        map[ToolsetID]bool
	defaultToolsetIDs   []ToolsetID
	toolsetDescriptions map[ToolsetID]string

	readOnly             bool
	enabledToolsets      map[ToolsetID]bool // nil means all enabled
	additionalTools      map[string]bool
	featureChecker       FeatureFlagChecker
	filters              []ToolFilter
	unrecognizedToolsets []string
	instructions         string
}

// UnrecognizedToolsets returns toolset IDs requested via WithToolsets that do
// not match any registered toolset — useful for warning about typos.
func (r *Inventory) UnrecognizedToolsets() []string { return r.unrecognizedToolsets }

// ToolsetIDs returns all toolset IDs present in the manifest, sorted.
func (r *Inventory) ToolsetIDs() []ToolsetID { return r.toolsetIDs }

// DefaultToolsetIDs returns the IDs of toolsets marked Default, sorted.
func (r *Inventory) DefaultToolsetIDs() []ToolsetID { return r.defaultToolsetIDs }

// ToolsetDescriptions maps toolset ID to description.
func (r *Inventory) ToolsetDescriptions() map[ToolsetID]string { return r.toolsetDescriptions }

// HasToolset reports whether any tool/resource/prompt belongs to the toolset.
func (r *Inventory) HasToolset(id ToolsetID) bool { return r.toolsetIDSet[id] }

// Instructions returns the aggregated server instructions (empty unless
// WithServerInstructions was used).
func (r *Inventory) Instructions() string { return r.instructions }

// MCP method constants for use with ForMCPRequest.
const (
	MCPMethodInitialize             = "initialize"
	MCPMethodToolsList              = "tools/list"
	MCPMethodToolsCall              = "tools/call"
	MCPMethodResourcesList          = "resources/list"
	MCPMethodResourcesRead          = "resources/read"
	MCPMethodResourcesTemplatesList = "resources/templates/list"
	MCPMethodPromptsList            = "prompts/list"
	MCPMethodPromptsGet             = "prompts/get"
)

func (r *Inventory) isToolsetEnabled(id ToolsetID) bool {
	if r.enabledToolsets != nil {
		return r.enabledToolsets[id]
	}
	return true
}

// isToolEnabled applies the full filter pipeline, in order:
//  1. the tool's own Enabled function
//  2. the read-only filter
//  3. builder filters (feature-flag filter, WithFilter, WithExcludeTools)
//  4. additional-tools allow-list (bypasses toolset membership)
//  5. toolset membership
func (r *Inventory) isToolEnabled(ctx context.Context, tool *ServerTool) bool {
	if tool.Enabled != nil {
		enabled, err := tool.Enabled(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "inventory: Tool.Enabled error for %q: %v\n", tool.Tool.Name, err)
			return false
		}
		if !enabled {
			return false
		}
	}
	if r.readOnly && !tool.IsReadOnly() {
		return false
	}
	for _, filter := range r.filters {
		allowed, err := filter(ctx, tool)
		if err != nil {
			fmt.Fprintf(os.Stderr, "inventory: filter error for %q: %v\n", tool.Tool.Name, err)
			return false
		}
		if !allowed {
			return false
		}
	}
	if r.additionalTools != nil && r.additionalTools[tool.Tool.Name] {
		return true
	}
	return r.isToolsetEnabled(tool.Toolset.ID)
}

// AvailableTools returns the tools passing all filters, sorted by toolset ID
// then tool name for deterministic output.
func (r *Inventory) AvailableTools(ctx context.Context) []ServerTool {
	var result []ServerTool
	for i := range r.tools {
		if r.isToolEnabled(ctx, &r.tools[i]) {
			result = append(result, r.tools[i])
		}
	}
	sortTools(result)
	return result
}

// AvailableResourceTemplates returns resource templates passing the toolset and
// feature-flag filters, sorted.
func (r *Inventory) AvailableResourceTemplates(ctx context.Context) []ServerResourceTemplate {
	var result []ServerResourceTemplate
	for i := range r.resourceTemplates {
		res := &r.resourceTemplates[i]
		if r.featureChecker != nil && !featureFlagAllowed(ctx, r.featureChecker, res.FeatureFlagEnable, res.FeatureFlagDisable) {
			continue
		}
		if r.isToolsetEnabled(res.Toolset.ID) {
			result = append(result, *res)
		}
	}
	sortResourceTemplates(result)
	return result
}

// AvailablePrompts returns prompts passing the toolset and feature-flag
// filters, sorted.
func (r *Inventory) AvailablePrompts(ctx context.Context) []ServerPrompt {
	var result []ServerPrompt
	for i := range r.prompts {
		p := &r.prompts[i]
		if r.featureChecker != nil && !featureFlagAllowed(ctx, r.featureChecker, p.FeatureFlagEnable, p.FeatureFlagDisable) {
			continue
		}
		if r.isToolsetEnabled(p.Toolset.ID) {
			result = append(result, *p)
		}
	}
	sortPrompts(result)
	return result
}

// AllTools returns all tools without filtering, sorted.
func (r *Inventory) AllTools() []ServerTool {
	result := slices.Clone(r.tools)
	sortTools(result)
	return result
}

// AvailableToolsets returns the toolsets that contain at least one tool, sorted
// by ID. Pass toolset IDs to exclude from the result.
func (r *Inventory) AvailableToolsets(exclude ...ToolsetID) []ToolsetMetadata {
	excludeSet := make(map[ToolsetID]bool, len(exclude))
	for _, id := range exclude {
		excludeSet[id] = true
	}
	byID := make(map[ToolsetID]ToolsetMetadata)
	for i := range r.tools {
		ts := r.tools[i].Toolset
		if _, ok := byID[ts.ID]; !ok {
			byID[ts.ID] = ts
		}
	}
	var result []ToolsetMetadata
	for _, id := range r.toolsetIDs {
		if excludeSet[id] {
			continue
		}
		if ts, ok := byID[id]; ok {
			result = append(result, ts)
		}
	}
	return result
}

// EnabledToolsets returns the toolsets enabled under the current filters.
func (r *Inventory) EnabledToolsets() []ToolsetMetadata {
	all := r.AvailableToolsets()
	if r.enabledToolsets == nil {
		return all
	}
	var result []ToolsetMetadata
	for _, ts := range all {
		if r.enabledToolsets[ts.ID] {
			result = append(result, ts)
		}
	}
	return result
}

// RegisterTools registers all available tools with the server.
func (r *Inventory) RegisterTools(ctx context.Context, s *mcp.Server, deps any, middleware ...ToolHandlerMiddleware) {
	for _, tool := range r.AvailableTools(ctx) {
		tool.RegisterFunc(s, deps, middleware...)
	}
}

// RegisterResourceTemplates registers all available resource templates.
func (r *Inventory) RegisterResourceTemplates(ctx context.Context, s *mcp.Server, deps any) {
	for _, res := range r.AvailableResourceTemplates(ctx) {
		templateCopy := res.Template
		s.AddResourceTemplate(&templateCopy, res.Handler(deps))
	}
}

// RegisterPrompts registers all available prompts.
func (r *Inventory) RegisterPrompts(ctx context.Context, s *mcp.Server) {
	for _, prompt := range r.AvailablePrompts(ctx) {
		promptCopy := prompt.Prompt
		s.AddPrompt(&promptCopy, prompt.Handler)
	}
}

// RegisterAll registers all available tools, resources, and prompts.
func (r *Inventory) RegisterAll(ctx context.Context, s *mcp.Server, deps any, middleware ...ToolHandlerMiddleware) {
	r.RegisterTools(ctx, s, deps, middleware...)
	r.RegisterResourceTemplates(ctx, s, deps)
	r.RegisterPrompts(ctx, s)
}

// ResolveToolAliases resolves deprecated tool aliases to canonical names,
// logging a warning for each. Returns the resolved names and the map of
// aliases that were used.
func (r *Inventory) ResolveToolAliases(toolNames []string) (resolved []string, aliasesUsed map[string]string) {
	resolved = make([]string, 0, len(toolNames))
	aliasesUsed = make(map[string]string)
	for _, name := range toolNames {
		if canonical, isAlias := r.deprecatedAliases[name]; isAlias {
			fmt.Fprintf(os.Stderr, "inventory: tool %q is deprecated, use %q instead\n", name, canonical)
			aliasesUsed[name] = canonical
			resolved = append(resolved, canonical)
		} else {
			resolved = append(resolved, name)
		}
	}
	return resolved, aliasesUsed
}

// FindToolByName searches all tools (ignoring filters) for one with the given
// name.
func (r *Inventory) FindToolByName(toolName string) (*ServerTool, ToolsetID, error) {
	for i := range r.tools {
		if r.tools[i].Tool.Name == toolName {
			return &r.tools[i], r.tools[i].Toolset.ID, nil
		}
	}
	return nil, "", NewToolDoesNotExistError(toolName)
}

func (r *Inventory) filterToolsByName(name string) []ServerTool {
	var result []ServerTool
	for i := range r.tools {
		if r.tools[i].Tool.Name == name {
			result = append(result, r.tools[i])
		}
	}
	if len(result) > 0 {
		return result
	}
	if canonical, isAlias := r.deprecatedAliases[name]; isAlias {
		for i := range r.tools {
			if r.tools[i].Tool.Name == canonical {
				result = append(result, r.tools[i])
			}
		}
	}
	return result
}

func (r *Inventory) filterPromptsByName(name string) []ServerPrompt {
	for i := range r.prompts {
		if r.prompts[i].Prompt.Name == name {
			return []ServerPrompt{r.prompts[i]}
		}
	}
	return nil
}

// ForMCPRequest returns an Inventory trimmed to only the items relevant to a
// specific MCP request. This lets a server that builds a fresh instance per
// request register just the one tool a tools/call needs rather than the whole
// manifest. All existing filters still apply to the returned items.
func (r *Inventory) ForMCPRequest(method string, itemName string) *Inventory {
	result := &Inventory{
		tools:                r.tools,
		resourceTemplates:    r.resourceTemplates,
		prompts:              r.prompts,
		deprecatedAliases:    r.deprecatedAliases,
		toolsetIDs:           r.toolsetIDs,
		toolsetIDSet:         r.toolsetIDSet,
		defaultToolsetIDs:    r.defaultToolsetIDs,
		toolsetDescriptions:  r.toolsetDescriptions,
		readOnly:             r.readOnly,
		enabledToolsets:      r.enabledToolsets,
		additionalTools:      r.additionalTools,
		featureChecker:       r.featureChecker,
		filters:              r.filters,
		unrecognizedToolsets: r.unrecognizedToolsets,
		instructions:         r.instructions,
	}

	clearAll := func() {
		result.tools = nil
		result.resourceTemplates = nil
		result.prompts = nil
	}

	switch method {
	case MCPMethodInitialize:
		clearAll()
	case MCPMethodToolsList:
		result.resourceTemplates, result.prompts = nil, nil
	case MCPMethodToolsCall:
		result.resourceTemplates, result.prompts = nil, nil
		if itemName != "" {
			result.tools = r.filterToolsByName(itemName)
		}
	case MCPMethodResourcesList, MCPMethodResourcesTemplatesList, MCPMethodResourcesRead:
		result.tools, result.prompts = nil, nil
	case MCPMethodPromptsList:
		result.tools, result.resourceTemplates = nil, nil
	case MCPMethodPromptsGet:
		result.tools, result.resourceTemplates = nil, nil
		if itemName != "" {
			result.prompts = r.filterPromptsByName(itemName)
		}
	default:
		clearAll()
	}

	return result
}

// generateInstructions aggregates per-toolset InstructionsFunc output for the
// enabled toolsets into a single instructions string.
func generateInstructions(r *Inventory) string {
	var b strings.Builder
	seen := make(map[ToolsetID]bool)
	for i := range r.tools {
		ts := r.tools[i].Toolset
		if seen[ts.ID] || ts.InstructionsFunc == nil {
			continue
		}
		seen[ts.ID] = true
		if !r.isToolsetEnabled(ts.ID) {
			continue
		}
		if s := ts.InstructionsFunc(r); s != "" {
			if b.Len() > 0 {
				b.WriteString("\n\n")
			}
			b.WriteString(s)
		}
	}
	return b.String()
}
