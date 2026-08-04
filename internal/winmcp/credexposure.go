//go:build windows && (amd64 || arm64)

package winmcp

import (
	"encoding/json"
	"os"

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

// perceptionToolsets can read a secret back off the *screen* once it has been
// typed somewhere unmasked: Screenshot returns it as pixels, GetText reads it out
// of an unmasked control, and Clipboard returns a copied selection.
//
// They are not risky on their own. Injection normally requires a destination that
// reports itself as masked (see desktop.requireMaskedFocus), which closes this
// path — the agent may choose where the keystrokes go, but not to somewhere it
// can read them back. A credential declaring allow_unmasked_target gives that up,
// and only then does a perception toolset become a credential-disclosure surface.
var perceptionToolsets = []string{
	string(windows.ToolsetScreen.ID),
	string(windows.ToolsetInteraction.ID),
	string(windows.ToolsetSystem.ID), // Clipboard
}

// credentialsDeclareUnmaskedTargets reports whether any entry in the credentials
// document opts out of the masked-destination check.
//
// It decodes only that flag. The secret fields are deliberately not part of the
// struct, so this runs before startup admission without materialising a
// plaintext — the file's DACL is still checked, and the real load (which does
// decode secrets, into wipeable bytes) happens later and only if admitted.
//
// A malformed document is not diagnosed here; it reports false and lets
// loadCredentialsFile produce the real error, so there is one place that decides
// whether a credentials file is valid.
func credentialsDeclareUnmaskedTargets(path string) bool {
	if path == "" {
		return false
	}
	if err := checkCredentialsFileACL(path); err != nil {
		return false
	}
	raw, err := os.ReadFile(path) //nolint:gosec // an operator-supplied path, ACL-checked above
	if err != nil {
		return false
	}
	var doc struct {
		Credentials []struct {
			AllowUnmaskedTarget bool `json:"allow_unmasked_target"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return false
	}
	for _, c := range doc.Credentials {
		if c.AllowUnmaskedTarget {
			return true
		}
	}
	return false
}

// exposureToolsets returns the toolsets whose presence puts installed credentials
// at risk, given whether any credential opts out of the masked-destination check.
func exposureToolsets(anyUnmaskedTarget bool) []string {
	if !anyUnmaskedTarget {
		return riskyCredentialToolsets
	}
	return append(append([]string{}, riskyCredentialToolsets...), perceptionToolsets...)
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
	anyUnmaskedTarget bool,
) (unacknowledged, acknowledged []string) {
	served := make(map[string]bool, len(enabled))
	for _, ts := range enabled {
		served[string(ts.ID)] = true
	}
	for _, r := range exposureToolsets(anyUnmaskedTarget) {
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
