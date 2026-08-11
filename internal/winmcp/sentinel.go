//go:build windows && (amd64 || arm64)

package winmcp

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"

	"github.com/deploymenttheory/agentweave-harness/guardrails/audit"
)

// sentinelToken mints the token a kill sentinel must carry, and tells the
// operator what it is.
//
// The sentinel used to be authenticated by its own existence: any file named
// "kill" in the control directory tripped the containment ladder. That made it
// the one authoritative trigger an agent could fire by itself — a single
// FileSystem write, or any PowerShell redirect, and a policy with isolate or
// shutdown armed did exactly that. It is the escalation the design is explicit
// that an agent must never be able to ask for, since the agent-facing Kill tool
// is deliberately routed away from containment for the same reason.
//
// The token is minted per session and written nowhere: it goes to the log and the
// audit chain, both of which the operator reads and neither of which the agent
// can write. Putting it in a file beside the sentinel would hand it back to
// anything that can read the control directory, which is the position the agent
// is in.
//
// An empty control directory means the trigger is not configured, so there is
// nothing to authenticate.
func sentinelToken(controlDir string, auditLog *audit.AuditLog, logger *slog.Logger) string {
	if controlDir == "" {
		return ""
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		// Fail closed. Returning "" would restore the old behaviour — presence
		// alone trips — which is the vulnerability. A token nothing can match
		// leaves the sentinel unusable and says so, and every other trigger
		// (posture drift, rug-pull, heartbeat gap, the status endpoint) still works.
		if logger != nil {
			logger.Error("could not mint a kill-sentinel token; the sentinel trigger is disabled "+
				"for this session. Use the status endpoint's /revoke, or restart the server",
				"error", err)
		}
		return "sentinel-unavailable-" + err.Error()
	}
	token := hex.EncodeToString(raw)

	if logger != nil {
		logger.Info("kill sentinel armed: write this token into the 'kill' file to trip it",
			"control_dir", controlDir, "token", token)
	}
	if auditLog != nil {
		// The token is in the chain so an investigator can tell an operator-authored
		// trip from a rejected one. It authorises a shutdown, not access to data, and
		// the chain is already the record of everything else this session did.
		_, _ = auditLog.Append("killswitch.sentinel_armed", map[string]any{
			"control_dir": controlDir,
			"token":       token,
		})
	}
	return token
}
