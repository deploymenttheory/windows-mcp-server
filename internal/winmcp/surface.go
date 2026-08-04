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
	// deps backs the inject-deps layer, held until installReceiving runs because
	// the whole chain must be installed in a single call — see installReceiving.
	deps windows.ToolDependencies
}

// newMCPSurface builds the server. It installs no middleware: every entry point
// must call installReceiving exactly once, with the layers that belong inside the
// two unconditional ones.
func newMCPSurface(
	cfg Config,
	inv *inventory.Inventory,
	personaInstructions string,
	deps windows.ToolDependencies,
) *mcpSurface {
	s := &mcpSurface{
		Capabilities: pinnedCapabilities(),
		Instructions: combineInstructions(personaInstructions, inv.Instructions()),
		deps:         deps,
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
	return s
}

// installReceiving installs the whole receiving chain, outermost first: inject
// deps, cache hints, then inner.
//
// It must be ONE call, and that is the entire reason this method exists.
// AddReceivingMiddleware composes the middleware handed to a single call
// outermost-first, but each separate call wraps the chain built so far — so
// across several calls the last middleware added ends up outermost, the reverse
// of the order intended. Installing across calls put the policy engine outside
// the audit layer, and a refused call therefore produced no tool.call entry at
// all: the refusals are precisely the events the chain exists to hold.
//
// Dependency injection has to be outermost for every other layer to read deps
// from the context, and the cache hints have to sit outside the guardrails so
// nothing inside can undo the envelope they set.
// TestReceivingMiddlewareRunsOutermostFirst pins the resulting order.
func (s *mcpSurface) installReceiving(inner ...mcp.Middleware) {
	chain := make([]mcp.Middleware, 0, len(inner)+2)
	chain = append(chain, windows.InjectDepsMiddleware(s.deps), cacheHintsMiddleware())
	chain = append(chain, inner...)
	s.Server.AddReceivingMiddleware(chain...)
}
