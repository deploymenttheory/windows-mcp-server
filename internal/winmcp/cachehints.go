//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Caching hints for the six result types protocol 2026-07-28 marks cacheable
// (SEP-2549): tools/list, prompts/list, resources/list, resources/templates/list,
// resources/read and server/discover.
//
// The SDK already fills these in — cacheScope "public", ttlMs 0 — which is
// structurally conformant but says something untrue about this server. Both
// values are set deliberately here instead.
const (
	// manifestTTL is how long a client may treat the served manifest as fresh.
	//
	// The manifest is built once at startup from the resolved toolsets and cannot
	// change while the process runs; the rug-pull detector trips the kill switch if
	// it ever does. So a client caching it for the whole session is never wrong.
	// The bound exists only so a client that outlives a restart re-reads rather than
	// carrying a manifest from a differently-configured run.
	manifestTTL = 5 * time.Minute

	// stateTTL is the freshness of a resources/read result. Every fixed resource is
	// a view of live desktop or system state — the focused window, the display
	// layout, the recording status — so any cached copy is already potentially
	// stale. Zero is the spec's "immediately stale", which is the honest answer.
	stateTTL = 0

	// cacheScopePrivate marks a result that a shared intermediary must not cache
	// and serve to another caller.
	//
	// The SDK's "public" default is wrong for this server in both directions. A
	// resources/read returns one user's desktop, so a shared cache serving it on is
	// an information disclosure. The manifests are no better: which tools exist
	// depends on the persona, toolset selection and read-only stance this session
	// was started with, so another caller's answer is a different answer.
	cacheScopePrivate = "private"
)

// cacheHintsMiddleware overwrites the SDK's default caching hints with ones that
// describe this server.
//
// It is receiving middleware, so it runs after the handler has produced the
// result and can amend the envelope on the way out. Only the envelope is touched:
// the rug-pull fingerprints deliberately ignore these fields (see
// TestHashToolsIgnoresResultEnvelope), so amending them here cannot read as drift.
func cacheHintsMiddleware() mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			res, err := next(ctx, method, req)
			if err != nil {
				return res, err
			}
			switch r := res.(type) {
			case *mcp.ListToolsResult:
				r.Cacheable = manifestCacheable()
			case *mcp.ListPromptsResult:
				r.Cacheable = manifestCacheable()
			case *mcp.ListResourcesResult:
				r.Cacheable = manifestCacheable()
			case *mcp.ListResourceTemplatesResult:
				r.Cacheable = manifestCacheable()
			case *mcp.DiscoverResult:
				r.Cacheable = manifestCacheable()
			case *mcp.ReadResourceResult:
				r.Cacheable = mcp.Cacheable{TTLMs: stateTTL, CacheScope: cacheScopePrivate}
			}
			return res, err
		}
	}
}

func manifestCacheable() mcp.Cacheable {
	return mcp.Cacheable{
		TTLMs:      int(manifestTTL / time.Millisecond),
		CacheScope: cacheScopePrivate,
	}
}
