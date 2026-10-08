//go:build windows && (amd64 || arm64)

package winmcp

import (
	"fmt"

	"github.com/deploymenttheory/agentweave-harness/guardrails/evidence"
	"github.com/deploymenttheory/mcp-server-core/runtime"
)

// The operator-facing operations behind the `evidence` subcommands. The
// bundling and verification live in mcp-server-core/runtime; these are the
// CLI's entry points.

// BundleEvidence gathers a session's evidence from an audit directory — its
// audit chain, the extracted verdicts, and any recording — and seals it into a
// signed (or, without a key, unsigned) archive.
func BundleEvidence(auditDir, session, recordingDir, outPath, keyFile string) (evidence.Manifest, error) {
	man, err := runtime.BundleEvidence(auditDir, session, recordingDir, outPath, keyFile)
	if err != nil {
		return evidence.Manifest{}, fmt.Errorf("evidence: %w", err)
	}
	return man, nil
}

// VerifyEvidence checks a bundle against its manifest and, when given, an
// expected public key.
func VerifyEvidence(zipPath, pubKeyHex string) (evidence.Report, error) {
	rep, err := runtime.VerifyEvidence(zipPath, pubKeyHex)
	if err != nil {
		return evidence.Report{}, fmt.Errorf("evidence: %w", err)
	}
	return rep, nil
}
