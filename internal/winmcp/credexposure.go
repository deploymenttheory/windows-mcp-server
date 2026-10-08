//go:build windows && (amd64 || arm64)

package winmcp

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/deploymenttheory/agentweave-harness/guardrails/audit"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
	"github.com/deploymenttheory/mcp-server-core/inventory"
	"github.com/deploymenttheory/mcp-server-core/surface"
	"github.com/deploymenttheory/windows-mcp-server/pkg/windows"
)

// credentialExposure names the toolsets that put installed credentials at risk
// on Windows.
//
// Risky: shell can read a generic credential back out of the calling user's
// Credential Manager (CredRead via PowerShell), and filesystem can copy a
// Credential Manager backup. Perception: screen, interaction (GetText) and
// system (Clipboard) can read a secret back off the screen once it has been
// typed somewhere unmasked, which only an allow_unmasked_target entry permits
// (see desktop.requireMaskedFocus).
var credentialExposure = surface.CredentialExposure{
	Risky: []string{
		string(windows.ToolsetShell.ID),
		string(windows.ToolsetFilesystem.ID),
	},
	Perception: []string{
		string(windows.ToolsetScreen.ID),
		string(windows.ToolsetInteraction.ID),
		string(windows.ToolsetSystem.ID), // Clipboard
	},
}

// credentialsDeclareUnmaskedTargets reports whether any entry in the
// credentials document opts out of the masked-destination check, after the
// same DACL check the real loader applies. It decodes only that flag, so it
// runs before startup admission without materialising a plaintext.
func credentialsDeclareUnmaskedTargets(path string) bool {
	return surface.CredentialsDeclareUnmaskedTargets(path, checkCredentialsFileACL)
}

// ErrCredentialExposureDenied reports a --credentials-file served alongside a
// toolset that can read the installed credentials back (shell or filesystem)
// without the policy acknowledging the exposure. It is a configuration error,
// not a device denial: the fix is to the toolset selection or the policy
// document, so it is not routed through the guardrail decision.
var ErrCredentialExposureDenied = errors.New(
	"credentials exposed to a toolset that can read them back",
)

// refuseCredentialExposure applies the exposure rule before anything is
// installed. Installed credentials live in the calling user's Credential
// Manager, so a toolset that can read that back defeats the never-read
// guarantee. Refuse rather than serve a weaker posture than the document
// describes — the same stance the firewall tiers take — unless the policy
// explicitly accepts it; the acknowledged case is logged so the trade-off is
// visible.
func refuseCredentialExposure(
	cfg Config,
	inv *inventory.Inventory,
	devicePolicy *policy.Policy,
	auditLog *audit.AuditLog,
	logger *slog.Logger,
) error {
	if cfg.CredentialsFile == "" {
		return nil
	}
	unacked, acked := credentialExposure.Split(
		inv.EnabledToolsets(),
		devicePolicy.Credentials.AcknowledgeToolsetExposure,
		credentialsDeclareUnmaskedTargets(cfg.CredentialsFile),
	)
	if len(unacked) > 0 {
		if auditLog != nil {
			_, _ = auditLog.Append("credentials.exposure.denied", map[string]any{
				"credentials_file": true,
				"exposed_toolsets": unacked,
			})
			_ = auditLog.Flush()
		}
		return fmt.Errorf("%w: the %v toolset(s) can read installed credentials back out of the "+
			"Credential Manager; remove them, or acknowledge the exposure in the policy document "+
			"(credentials.acknowledge_toolset_exposure)", ErrCredentialExposureDenied, unacked)
	}
	if len(acked) > 0 {
		logger.Warn(
			"credentials served alongside toolsets that can read them back; exposure acknowledged in policy",
			"toolsets",
			acked,
		)
		if auditLog != nil {
			_, _ = auditLog.Append("credentials.exposure.acknowledged", map[string]any{
				"exposed_toolsets": acked,
			})
		}
	}
	return nil
}
