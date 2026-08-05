//go:build windows && (amd64 || arm64)

package winmcp

import (
	"log/slog"
	"os"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/export"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy"
)

// secretEnvVars are the environment variables holding a secret this server reads
// once at startup. They are supplied through the environment rather than through
// flags because argv is world-readable — which only helps for as long as the
// value stays out of reach of anything the model can drive.
var secretEnvVars = []string{
	"WINDOWS_MCP_AUDIT_KEY",           // forging the audit chain
	"WINDOWS_MCP_APPROVAL_KEY",        // forging a dual-control approval
	"WINDOWS_MCP_GRAPH_CLIENT_SECRET", // a tenant-wide Entra app secret
	"WINDOWS_MCP_REMOTE_POLICY_TOKEN", // impersonating the device to the PDP
	"WINDOWS_MCP_OTLP_HEADERS",        // collector credentials
	"WINDOWS_MCP_EVIDENCE_KEY_FILE",   // path to the evidence signing key
	// The evidence export destinations. A pre-signed URL carries its signature in
	// the query string, so the whole URL is a write credential for the evidence
	// bucket -- which is why these are WINDOWS_MCP_-prefixed rather than named the
	// way each vendor's SDK expects. The prefix is what internal/desktop withholds
	// from every child process; a bare AWS_SECRET_ACCESS_KEY or AZURE_CLIENT_SECRET
	// would be readable by any PowerShell the agent runs.
	export.EnvSignedURL,
	export.EnvSignedURLManifest,
	export.EnvSignedURLSignature,
}

// scrubSecretEnv removes the startup secrets from this process's environment,
// once every component that needs them holds its own copy.
//
// It is the second of two defences, and it exists because the first cannot be
// complete. internal/desktop withholds every WINDOWS_MCP_* variable when it
// builds a child environment, which covers PowerShell and ffmpeg — but any future
// code path that spawns a process without going through powerShellEnv would
// inherit the parent environment as it stands. Clearing the values here means
// there is nothing left to inherit, whatever route a child is started by.
//
// It also covers the two variables the prefix rule cannot know about: the egress
// proxy's shared secret and the status endpoint's bearer token are named *by the
// policy document*, so their variables can be called anything at all.
//
// Order matters. Call this only after the audit log, the approvals client, the
// signal registry, the telemetry exporter and the egress proxy have been
// constructed; each reads its secret exactly once, at startup, into the struct
// that uses it.
func scrubSecretEnv(devicePolicy *policy.Policy, logger *slog.Logger) {
	names := make([]string, 0, len(secretEnvVars)+2)
	names = append(names, secretEnvVars...)
	if devicePolicy != nil && devicePolicy.Egress.AuthTokenEnv != "" {
		names = append(names, devicePolicy.Egress.AuthTokenEnv)
	}
	// The status token reaches POST /revoke, which runs the containment ladder --
	// so it is at least as worth clearing as the proxy credential beside it.
	if devicePolicy != nil && devicePolicy.Transparency.StatusTokenEnv != "" {
		names = append(names, devicePolicy.Transparency.StatusTokenEnv)
	}

	cleared := 0
	for _, name := range names {
		if _, present := os.LookupEnv(name); !present {
			continue
		}
		if err := os.Unsetenv(name); err != nil {
			// Not fatal: internal/desktop still withholds the whole WINDOWS_MCP_*
			// prefix from children, so this is defence in depth failing back to one
			// layer rather than none. Say so plainly instead of failing startup.
			if logger != nil {
				logger.Warn("could not clear a secret from the environment; "+
					"it remains readable by any process started outside powerShellEnv",
					"variable", name, "error", err)
			}
			continue
		}
		cleared++
	}
	if cleared > 0 && logger != nil {
		logger.Debug("cleared startup secrets from the process environment", "count", cleared)
	}
}
