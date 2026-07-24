// Package inventory is a transport-agnostic, domain-agnostic registry for MCP
// tools, resources, and prompts. It groups them into toolsets and supports
// filtering (read-only, toolset selection, allow/deny lists, feature flags,
// arbitrary predicates) so that callers can assemble different surfaces — for
// example, per-persona presets — from a single flat manifest.
//
// It is deliberately independent of any particular domain: tool dependencies
// are typed as `any` and resolved by the domain package (e.g. pkg/windows)
// which retrieves them from the request context. This mirrors the design of
// github-mcp-server's pkg/inventory.
package inventory

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// HandlerFunc generates an MCP tool handler from dependencies. Handlers are
// generated on demand at registration time so that ServerTool values can be
// passed around and filtered without materializing handlers. The deps
// parameter is typed as `any` to avoid a dependency from this generic package
// onto any concrete domain type. Context-based constructors ignore deps and
// retrieve dependencies from the request context instead.
type HandlerFunc func(deps any) mcp.ToolHandler

// ToolHandlerMiddleware wraps an MCP tool handler. Middleware is applied from
// last to first, so the first middleware passed to RegisterFunc executes
// closest to the transport (outermost).
type ToolHandlerMiddleware func(next mcp.ToolHandler) mcp.ToolHandler

// ToolsetID is a unique identifier for a toolset. A distinct type provides
// compile-time safety when passing toolset identifiers around.
type ToolsetID string

// ToolsetMetadata describes a toolset — a named group of related tools.
type ToolsetMetadata struct {
	// ID is the unique identifier for the toolset (e.g. "interaction", "system").
	ID ToolsetID
	// Description is a human-readable summary of the toolset.
	Description string
	// Default indicates the toolset is enabled when the caller asks for the
	// "default" configuration (or passes no explicit toolset selection).
	Default bool
	// Icon is an optional icon hint for UIs. It is metadata only.
	Icon string
	// InstructionsFunc, if set, returns server instructions contributed by this
	// toolset. It receives the built Inventory so it can consider what else is
	// enabled.
	InstructionsFunc func(inv *Inventory) string
}

// ServerTool is an MCP tool paired with its toolset membership and a lazy
// handler generator, plus optional gating metadata.
type ServerTool struct {
	// Tool is the MCP tool definition (name, description, schema, annotations).
	Tool mcp.Tool
	// Toolset records which toolset this tool belongs to.
	Toolset ToolsetMetadata
	// HandlerFunc generates the handler when given dependencies.
	HandlerFunc HandlerFunc

	// FeatureFlagEnable, if set, requires the named feature flag to be enabled
	// for the tool to be available.
	FeatureFlagEnable string
	// FeatureFlagDisable lists feature flags that, if any is enabled, omit this
	// tool.
	FeatureFlagDisable []string
	// Enabled, if set, is consulted at filter time to decide availability. A nil
	// Enabled means "enabled" (subject to the other filters). On error the tool
	// is treated as disabled.
	Enabled func(ctx context.Context) (bool, error)

	// RequiredScopes and AcceptedScopes are optional permission metadata for
	// tools. They are unused by the core filter pipeline but provide an
	// extension point for scope/permission-based filtering via WithFilter.
	RequiredScopes []string
	AcceptedScopes []string
}

// IsReadOnly reports whether the tool is annotated read-only.
func (st *ServerTool) IsReadOnly() bool {
	return st.Tool.Annotations != nil && st.Tool.Annotations.ReadOnlyHint
}

// HasHandler reports whether the tool has a handler generator.
func (st *ServerTool) HasHandler() bool { return st.HandlerFunc != nil }

// Handler materializes the tool's handler with the given dependencies. It
// panics if HandlerFunc is nil — every registered tool must have a handler.
func (st *ServerTool) Handler(deps any) mcp.ToolHandler {
	if st.HandlerFunc == nil {
		panic("inventory: HandlerFunc is nil for tool: " + st.Tool.Name)
	}
	return st.HandlerFunc(deps)
}

// RegisterFunc registers the tool with the MCP server, wrapping the handler in
// the supplied middleware (first middleware = outermost). A shallow copy of the
// tool is registered so the original ServerTool is never mutated.
func (st *ServerTool) RegisterFunc(s *mcp.Server, deps any, middleware ...ToolHandlerMiddleware) {
	handler := st.Handler(deps)
	for i := len(middleware) - 1; i >= 0; i-- {
		handler = middleware[i](handler)
	}
	toolCopy := st.Tool
	s.AddTool(&toolCopy, handler)
}

// NewServerToolWithContextHandler creates a ServerTool whose typed handler
// retrieves dependencies from the request context (injected via middleware)
// rather than from a registration-time closure. The In value is unmarshaled
// from the raw call arguments; the Out value is currently ignored by this
// low-level constructor (domain helpers may use it for structured output).
//
// This is the preferred constructor: it avoids allocating a closure per tool at
// registration time, which matters for servers that build a fresh instance per
// request.
func NewServerToolWithContextHandler[In any, Out any](tool mcp.Tool, toolset ToolsetMetadata, handler func(ctx context.Context, req *mcp.CallToolRequest, args In) (*mcp.CallToolResult, Out, error)) ServerTool {
	return ServerTool{
		Tool:    tool,
		Toolset: toolset,
		HandlerFunc: func(_ any) mcp.ToolHandler {
			return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				var args In
				if len(req.Params.Arguments) > 0 {
					if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
						return &mcp.CallToolResult{
							Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("invalid arguments: %s", err)}},
							IsError: true,
						}, nil
					}
				}
				result, _, err := handler(ctx, req, args)
				return result, err
			}
		},
	}
}

// NewServerTool creates a ServerTool from a raw mcp.ToolHandler that retrieves
// dependencies from the request context. Use this when the handler needs the
// raw request rather than typed, pre-unmarshaled arguments.
func NewServerTool(tool mcp.Tool, toolset ToolsetMetadata, handler mcp.ToolHandler) ServerTool {
	return ServerTool{
		Tool:    tool,
		Toolset: toolset,
		HandlerFunc: func(_ any) mcp.ToolHandler {
			return handler
		},
	}
}
