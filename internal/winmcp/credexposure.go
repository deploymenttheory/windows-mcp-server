//go:build windows && (amd64 || arm64)

package winmcp

import (
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy"
	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
	"github.com/deploymenttheory/windows-mcp-server/pkg/windows"
)

// riskyCredentialToolsets are the toolsets that can read an installed generic
// credential back out of the calling user's Credential Manager, defeating the
// never-read guarantee: shell (CredRead via PowerShell) and filesystem (a
// Credential Manager backup is a file). This is the canonical list the 0.3
// refusal is built on.
var riskyCredentialToolsets = []string{
	string(windows.ToolsetShell.ID),
	string(windows.ToolsetFilesystem.ID),
}

// splitCredentialExposure partitions the risky toolsets that are actually served
// into those the policy acknowledges and those it does not, preserving the
// canonical order. A non-empty unacknowledged list is what forces a startup
// refusal; the acknowledged list is what gets recorded when startup proceeds
// anyway. The order of the two returns matches riskyCredentialToolsets so the
// audit record and the error message are stable.
func splitCredentialExposure(
	enabled []inventory.ToolsetMetadata,
	ack policy.StringSet,
) (unacknowledged, acknowledged []string) {
	served := make(map[string]bool, len(enabled))
	for _, ts := range enabled {
		served[string(ts.ID)] = true
	}
	for _, r := range riskyCredentialToolsets {
		if !served[r] {
			continue
		}
		if ack.Contains(r) {
			acknowledged = append(acknowledged, r)
		} else {
			unacknowledged = append(unacknowledged, r)
		}
	}
	return unacknowledged, acknowledged
}
