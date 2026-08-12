//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/agentweave-harness/guardrails/watch"
)

// receivingChain assembles RunStdio's receiving-middleware chain, outermost
// first, from the already-constructed layers. It exists as a seam so the one
// mode-dependent decision — how much of the local guardrail stack runs — is
// pinned by tests rather than buried in RunStdio.
//
// Standalone (or under an observe-mode harness), the full stack runs:
// audit → telemetry (when configured) → the rug-pull layers → enforce,
// enforce innermost so nothing routes around it while audit and rug-pull still
// observe what it refuses.
//
// Under an enforcing harness only the audit layer remains. The harness's
// decider already refused anything refusable before this process saw the
// frame, its own chain audits and fingerprints the wire, and running the
// local duplicates would double-decide every call — but the local audit
// middleware stays, because this host's chain is the record of what the
// process actually served, kept precisely so the harness's account of the
// session is not the only one.
func receivingChain(
	harnessEnforcing bool,
	auditMW mcp.Middleware,
	telemetryMW mcp.Middleware,
	rugpullMWs []mcp.Middleware,
	enforceMW mcp.Middleware,
) []mcp.Middleware {
	chain := []mcp.Middleware{auditMW}
	if harnessEnforcing {
		return chain
	}
	if telemetryMW != nil {
		chain = append(chain, telemetryMW)
	}
	chain = append(chain, rugpullMWs...)
	return append(chain, enforceMW)
}

// rugpullVerifier is the in-flight monitor's local rug-pull recheck. It is
// installed only alongside a pinned local baseline: under an enforcing harness
// there is none, because the fingerprints are taken from the wire where a
// tampered server cannot vouch for itself.
func rugpullVerifier(rp *watch.RugPull, tools func() []*mcp.Tool, trip func(string)) watch.VerifyFunc {
	return watch.VerifyFunc{
		Name: "rug-pull",
		Run:  func(context.Context) error { return rp.Recheck(tools()) },
		Trip: trip,
	}
}
