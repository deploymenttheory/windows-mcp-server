//go:build windows && (amd64 || arm64)

package winmcp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/evidence"
)

// verdictPrefixes are the audit events extracted into a bundle's verdicts.json —
// the decisions and containment record a reviewer looks at first, lifted out of
// the full chain for convenience (the chain itself is bundled too).
var verdictPrefixes = []string{
	"policy.decision", "devicePolicy.startup", "plan.", "approval.",
	"killswitch.", "credentials.exposure", "server.surface",
}

// BundleEvidence gathers a session's evidence from an audit directory — its audit
// chain, the extracted verdicts, and any recording — and seals it into a signed
// (or, without a key, unsigned) archive.
func BundleEvidence(auditDir, session, recordingDir, outPath, keyFile string) (evidence.Manifest, error) {
	sessionFile := filepath.Join(auditDir, "session-"+session+".audit.jsonl")

	// Read the chain to extract verdicts and the head. A broken chain is not a
	// reason to refuse — a bundle of a tampered chain is itself evidence — so a
	// verification error here does not stop the bundle; only an unreadable file does.
	entries, _ := audit.VerifyFile(sessionFile, nil)
	if entries == nil {
		if _, err := os.Stat(sessionFile); err != nil {
			return evidence.Manifest{}, fmt.Errorf("session audit file: %w", err)
		}
	}

	verdicts, head := extractVerdicts(entries)

	sources := []evidence.Source{
		{ArchivePath: "audit/" + filepath.Base(sessionFile), FilePath: sessionFile},
		{ArchivePath: "verdicts.json", Bytes: verdicts},
	}
	if manifestPath := filepath.Join(auditDir, audit.ManifestName); fileExists(manifestPath) {
		sources = append(sources, evidence.Source{ArchivePath: "audit/" + audit.ManifestName, FilePath: manifestPath})
	}
	for _, rec := range recordingFiles(recordingDir, session) {
		sources = append(sources, evidence.Source{ArchivePath: "recording/" + filepath.Base(rec), FilePath: rec})
	}

	var signer *evidence.Signer
	if keyFile != "" {
		s, err := evidence.LoadSigner(keyFile)
		if err != nil {
			return evidence.Manifest{}, fmt.Errorf("evidence bundle: %w", err)
		}
		signer = s
	}

	if outPath == "" {
		outPath = filepath.Join(auditDir, "session-"+session+".evidence.zip")
	}
	man, err := evidence.Seal(sources, evidence.SealOptions{
		OutPath:   outPath,
		Session:   session,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		AuditHead: head,
		Signer:    signer,
	})
	if err != nil {
		return evidence.Manifest{}, fmt.Errorf("evidence bundle: %w", err)
	}
	return man, nil
}

// VerifyEvidence checks a bundle against its manifest and, when given, an expected
// public key.
func VerifyEvidence(zipPath, pubKeyHex string) (evidence.Report, error) {
	rep, err := evidence.Verify(zipPath, pubKeyHex)
	if err != nil {
		return evidence.Report{}, fmt.Errorf("evidence verify: %w", err)
	}
	return rep, nil
}

// extractVerdicts pulls the decision-shaped entries out of the chain into a JSON
// array, and returns the chain head (last entry's hash).
func extractVerdicts(entries []audit.AuditEntry) (jsonArray []byte, head string) {
	var kept []audit.AuditEntry
	for _, e := range entries {
		if isVerdict(e.Event) {
			kept = append(kept, e)
		}
	}
	if n := len(entries); n > 0 {
		head = entries[n-1].EntryHash
	}
	b, err := json.MarshalIndent(kept, "", "  ")
	if err != nil {
		return []byte("[]"), head
	}
	return b, head
}

func isVerdict(event string) bool {
	for _, p := range verdictPrefixes {
		if strings.HasPrefix(event, p) {
			return true
		}
	}
	return false
}

func recordingFiles(dir, session string) []string {
	if dir == "" {
		return nil
	}
	matches, err := filepath.Glob(filepath.Join(dir, "session-"+session+".*"))
	if err != nil {
		return nil
	}
	return matches
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
