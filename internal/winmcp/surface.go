//go:build windows && (amd64 || arm64)

package winmcp

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
	"github.com/deploymenttheory/windows-mcp-server/pkg/windows"
)

// mcpSurface is the protocol-facing construction shared by every entry point:
// the stdio server operators run, the in-process capture used for the offline
// pre-flight, and the loopback HTTP host the official conformance suite connects
// to.
//
// It exists so those three cannot drift. Conformance evidence gathered against
// the HTTP host only transfers to the shipped stdio binary if both serve the same
// manifest, the same capabilities and the same instructions, through the same
// middleware — and the cheapest way to guarantee that is for one function to
// build all of it. TestSurfaceIsIdenticalAcrossTransports asserts the result.
type mcpSurface struct {
	Server *mcp.Server
	// Capabilities is the pinned capability set handed to the server, kept so the
	// rug-pull detector can baseline exactly what was advertised.
	Capabilities *mcp.ServerCapabilities
	// Instructions is the combined persona and toolset guidance, kept for the same
	// reason.
	Instructions string
}

// newMCPSurface builds the server and installs the two middlewares that are
// unconditional on every entry point.
//
// Callers add their own middleware afterwards. Receiving middleware is applied
// outermost-first, so anything a caller adds is nested inside these two — which is
// what the ordering requires: dependency injection has to be outermost for every
// other layer to see it, and the caching hints have to be outside the guardrails
// so nothing inside can undo the envelope they set.
func newMCPSurface(
	cfg Config,
	inv *inventory.Inventory,
	personaInstructions string,
	deps windows.ToolDependencies,
) *mcpSurface {
	s := &mcpSurface{
		Capabilities: pinnedCapabilities(),
		Instructions: combineInstructions(personaInstructions, inv.Instructions()),
	}
	s.Server = mcp.NewServer(&mcp.Implementation{
		Name:    "windows-mcp-server",
		Title:   "Windows MCP Server",
		Version: cfg.Version,
	}, &mcp.ServerOptions{
		Instructions:      s.Instructions,
		Capabilities:      s.Capabilities,
		CompletionHandler: completionHandler(inv),
	})
	s.Server.AddReceivingMiddleware(windows.InjectDepsMiddleware(deps))
	s.Server.AddReceivingMiddleware(cacheHintsMiddleware())
	return s
}
