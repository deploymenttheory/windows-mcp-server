//go:build windows && (amd64 || arm64)

package winmcp

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
)

// resolveStatusToken produces the bearer credential for the status endpoint,
// preferring the environment variable over the inline value.
//
// The endpoint's POST /revoke trips the kill switch and runs the whole
// containment ladder, so this is a trigger credential. Every other one --
// WINDOWS_MCP_AUDIT_KEY, _APPROVAL_KEY, _GRAPH_CLIENT_SECRET,
// _REMOTE_POLICY_TOKEN -- is read from the environment, and egress even takes the
// name of a variable rather than a value, on the stated grounds that the document
// is meant to be reviewable and checked in.
//
// status_token was the exception: an inline secret in a document that is
// registered as an agent-readable protected path, and that the shell toolset
// reaches with no protected-path check at all. An agent served either toolset
// could read it and actuate containment -- the escalation the per-session sentinel
// token was introduced to close, and the reason the agent-facing Kill tool routes
// to StopGracefully rather than the ladder.
//
// The inline form still works, because removing a schema key breaks documents
// that run today and unknown keys are rejected outright. It warns instead.
func resolveStatusToken(t policy.TransparencyPolicy, logger *slog.Logger) (string, error) {
	if name := t.StatusTokenEnv; name != "" {
		token := os.Getenv(name)
		if token == "" {
			// Fatal for the same reason the egress proxy's is: a status endpoint
			// serving without the credential the document asked for is a weaker
			// posture than the document describes, and /revoke is behind it.
			return "", fmt.Errorf(
				"transparency.status_token_env names %q, which is unset or empty: the status "+
					"endpoint exposes POST /revoke, so it must not run without its credential",
				name)
		}
		if t.StatusToken != "" && logger != nil {
			logger.Warn("both transparency.status_token and status_token_env are set; " +
				"using the environment variable and ignoring the inline value")
		}
		return token, nil
	}

	if t.StatusToken != "" && logger != nil {
		logger.Warn("transparency.status_token holds the status endpoint's credential inline in " +
			"the policy document, which the agent can read through the filesystem toolset and " +
			"which the shell toolset reaches with no protected-path check. POST /revoke behind " +
			"it trips the kill switch. Move it to status_token_env")
	}
	return t.StatusToken, nil
}
