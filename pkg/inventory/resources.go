package inventory

import "github.com/modelcontextprotocol/go-sdk/mcp"

// ResourceHandlerFunc generates an MCP resource handler from dependencies.
type ResourceHandlerFunc func(deps any) mcp.ResourceHandler

// ServerResourceTemplate pairs a resource template with its toolset metadata
// and a lazy handler generator.
type ServerResourceTemplate struct {
	Template           mcp.ResourceTemplate
	HandlerFunc        ResourceHandlerFunc
	Toolset            ToolsetMetadata
	FeatureFlagEnable  string
	FeatureFlagDisable []string
}

// HasHandler reports whether the resource has a handler generator.
func (sr *ServerResourceTemplate) HasHandler() bool { return sr.HandlerFunc != nil }

// Handler materializes the resource handler with the given dependencies.
func (sr *ServerResourceTemplate) Handler(deps any) mcp.ResourceHandler {
	if sr.HandlerFunc == nil {
		panic("inventory: HandlerFunc is nil for resource: " + sr.Template.Name)
	}
	return sr.HandlerFunc(deps)
}

// NewServerResourceTemplate creates a ServerResourceTemplate.
func NewServerResourceTemplate(toolset ToolsetMetadata, resourceTemplate mcp.ResourceTemplate, handlerFn ResourceHandlerFunc) ServerResourceTemplate {
	return ServerResourceTemplate{
		Template:    resourceTemplate,
		HandlerFunc: handlerFn,
		Toolset:     toolset,
	}
}

// ServerResource pairs a fixed-URI resource with its toolset metadata and a lazy
// handler generator.
//
// This is distinct from ServerResourceTemplate on purpose. The MCP server keeps
// resources and resource templates in two disjoint collections: resources/list
// paginates only the former and resources/templates/list only the latter. A
// server that registers templates alone answers resources/read correctly but
// returns an *empty* resources/list, so a client that only lists sees nothing.
// Fixed-URI resources therefore need their own registration path.
type ServerResource struct {
	Resource           mcp.Resource
	HandlerFunc        ResourceHandlerFunc
	Toolset            ToolsetMetadata
	FeatureFlagEnable  string
	FeatureFlagDisable []string
}

// HasHandler reports whether the resource has a handler generator.
func (sr *ServerResource) HasHandler() bool { return sr.HandlerFunc != nil }

// Handler materializes the resource handler with the given dependencies.
func (sr *ServerResource) Handler(deps any) mcp.ResourceHandler {
	if sr.HandlerFunc == nil {
		panic("inventory: HandlerFunc is nil for resource: " + sr.Resource.Name)
	}
	return sr.HandlerFunc(deps)
}

// NewServerResource creates a ServerResource.
func NewServerResource(toolset ToolsetMetadata, resource mcp.Resource, handlerFn ResourceHandlerFunc) ServerResource {
	return ServerResource{
		Resource:    resource,
		HandlerFunc: handlerFn,
		Toolset:     toolset,
	}
}
