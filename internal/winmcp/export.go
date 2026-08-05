//go:build windows && (amd64 || arm64)

package winmcp

import (
	"log/slog"
	"os"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/export"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/status"
)

// provisionExport builds the evidence-export sink for a configured destination and
// records the intent in the audit chain.
//
// It returns a nil sink when export is off, so the caller does not special-case
// it — export.Ship is never reached with a nil sink because autoSealEvidence
// checks first.
//
// A construction failure disables export with a warning rather than failing
// startup, the same contract as telemetry and anchoring: transparency is always
// on, but it never gates the session. The distinction from egress enforcement is
// deliberate — a policy that names applications and cannot elevate is serving a
// weaker posture than it describes, where an export that cannot start leaves the
// evidence exactly where it already was, on the device.
//
// It must be called before scrubSecretEnv: the credentials are read here, once,
// into the sink that uses them.
func provisionExport(
	devicePolicy *policy.Policy,
	auditLog *audit.AuditLog,
	logger *slog.Logger,
) export.Sink {
	e := devicePolicy.Transparency.Export
	if !e.Enabled() {
		return nil
	}

	cfg := export.Config{Provider: e.Provider, Timeout: e.Timeout.Std()}
	sink, err := export.New(cfg, exportCredentials())
	if err != nil {
		logger.Warn("evidence export disabled",
			"provider", e.Provider,
			"error", err,
			"hint", "the sealed bundle still lands in transparency.evidence_dir")
		_, _ = auditLog.Append("export.disabled", map[string]any{
			"provider": e.Provider,
			"error":    err.Error(),
		})
		return nil
	}

	// The intent goes in the chain here, at startup, because it cannot go in later:
	// the bundle contains the chain, so the chain is closed before the bundle is
	// sealed and the upload runs after that. The outcome is written to the export
	// receipt beside the bundle instead. See export.Receipt.
	_, _ = auditLog.Append("export.configured", map[string]any{
		"provider":    e.Provider,
		"destination": sink.Describe(),
		"timeout":     e.Timeout.String(),
	})
	logger.Info("evidence export configured",
		"provider", e.Provider, "destination", sink.Describe())

	warnExportEgress(devicePolicy, logger)
	return sink
}

// exportCredentials reads the destination secrets from the environment, once.
//
// They are never flags (argv is world-readable) and never policy fields (the
// document is a reviewable, checked-in artifact that the agent can read through
// the filesystem toolset). The names are fixed and WINDOWS_MCP_-prefixed, which is
// what puts them behind both defences: internal/desktop withholds that prefix from
// every child process, and scrubSecretEnv clears them from this one.
func exportCredentials() export.Credentials {
	return export.Credentials{
		SignedURLBundle:    os.Getenv(export.EnvSignedURL),
		SignedURLManifest:  os.Getenv(export.EnvSignedURLManifest),
		SignedURLSignature: os.Getenv(export.EnvSignedURLSignature),
	}
}

// exportStatus renders the export tier for the status snapshot, or nil when no
// bundle leaves this device.
//
// Nil for a configured-but-unbuildable destination too, and that is the honest
// answer: the operator asked for export, it is not running, and reporting the
// provider name here would let a watcher read intent as posture. The audit chain
// carries the export.disabled entry that says why.
func exportStatus(e policy.ExportPolicy, sink export.Sink) *status.ExportStatus {
	if sink == nil || !e.Enabled() {
		return nil
	}
	return &status.ExportStatus{Provider: e.Provider, Destination: sink.Describe()}
}

// warnExportEgress reports the one contradiction the policy loader cannot settle
// on its own.
//
// When egress is enabled the device may only reach the hosts egress.allow names,
// and a signed_url destination lives entirely in an environment variable — so
// there is no host in the document to check it against. Worse, the export runs
// from the audit-close defer, which is *after* the egress cleanup defer has
// already stopped the proxy, so the upload cannot be routed through it either.
// Under scoped or global enforcement the server's own image needs an outbound
// allow rule or the bundle never leaves.
//
// Said out loud rather than left to be discovered during a shutdown nobody is
// watching, and warned rather than refused, because the combination is legitimate.
func warnExportEgress(devicePolicy *policy.Policy, logger *slog.Logger) {
	if !devicePolicy.Egress.Enabled {
		return
	}
	logger.Warn("evidence export runs outside the egress proxy",
		"enforcement", devicePolicy.Egress.Enforcement(),
		"why", "the proxy is stopped before the session's evidence is sealed and shipped",
		"hint", "list the export destination host in egress.allow, and under scoped or "+
			"global enforcement give this server's own executable an outbound allow rule")
}
