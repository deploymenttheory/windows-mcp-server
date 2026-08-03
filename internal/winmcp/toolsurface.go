//go:build windows && (amd64 || arm64)

package winmcp

import (
	"os"
	"strings"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy"
	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
	"github.com/deploymenttheory/windows-mcp-server/pkg/windows"
)

// toolsOutsidePersona returns the --tools entries whose toolset is not among the
// enabled toolsets — the tools served only by the additional-tools bypass. A
// persona is a documented guarantee about the served surface, so widening it with
// --tools is refused; without a persona the operator is composing the surface by
// hand and the bypass is theirs to use. Unknown names (and the always-served
// GuardrailStatus/Kill, which belong to no toolset) are ignored.
func toolsOutsidePersona(tools []string, enabled []inventory.ToolsetMetadata) []string {
	enabledSet := make(map[string]bool, len(enabled))
	for _, ts := range enabled {
		enabledSet[string(ts.ID)] = true
	}
	membership := windows.ToolToolsets()

	var out []string
	for _, t := range tools {
		ts, ok := membership[t]
		if !ok {
			continue
		}
		if !enabledSet[ts] {
			out = append(out, t)
		}
	}
	return out
}

// protectedPaths lists the guardrail files the FileSystem tool must not touch:
// the credentials file (no read — a read is plaintext into the model's context —
// and no write), the audit log (no write), and the policy document (no write).
// Reading the audit log or the policy is allowed; both are meant to be inspected.
func protectedPaths(cfg Config, p *policy.Policy) []windows.ProtectedPath {
	var out []windows.ProtectedPath
	if cfg.CredentialsFile != "" {
		out = append(out, windows.NewProtectedPath(cfg.CredentialsFile, "the credentials file", false, true, true))
	}
	if cfg.PolicyConfig != "" {
		out = append(out, windows.NewProtectedPath(cfg.PolicyConfig, "the policy document", false, false, true))
	}
	if dest := p.Transparency.AuditDestination; dest != "" && dest != "stderr" {
		out = append(out, windows.NewProtectedPath(dest, "the audit log", auditDestinationIsDir(dest), false, true))
	}
	return out
}

// auditDestinationIsDir mirrors the audit package's directory detection: an explicit
// trailing separator, or an existing directory. A directory destination protects every
// session file and the manifest under it.
func auditDestinationIsDir(dest string) bool {
	if strings.HasSuffix(dest, "/") || strings.HasSuffix(dest, `\`) {
		return true
	}
	info, err := os.Stat(dest)
	return err == nil && info.IsDir()
}
