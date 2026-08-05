//go:build windows && (amd64 || arm64)

package winmcp

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/evidence"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/plan"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy"
)

// verdictPrefixes are the audit events extracted into a bundle's verdicts.json —
// the decisions and containment record a reviewer looks at first, lifted out of
// the full chain for convenience (the chain itself is bundled too).
var verdictPrefixes = []string{
	"policy.decided", "devicePolicy.decided", "plan.", "approval.",
	"killswitch.", "credentials.exposure", "server.configured",
	// A journey's own verdict. Without this a bundle sealed from a journey run
	// carried the plan.* entry for each step and no record of whether the journey
	// passed — the one line a reviewer opens the file to read.
	"journey.",
}

// BundleEvidence gathers a session's evidence from an audit directory — its audit
// chain, the extracted verdicts, and any recording — plus any extra sources the
// caller supplies (the full plan documents and closing posture, for an
// auto-seal), and seals it into a signed (or, without a key, unsigned) archive.
func BundleEvidence(
	auditDir, session, recordingDir, outPath, keyFile string,
	extra ...evidence.Source,
) (evidence.Manifest, error) {
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
	sources = append(sources, extra...)
	sources = dedupeSources(sources)

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

// autoSealEvidence seals a bundle into the evidence directory at session end,
// adding what only exists live: the full approved plan documents and the closing
// posture snapshot. It never crashes shutdown — a seal failure or a panic is
// logged and swallowed, because a missing bundle must not turn a clean exit into a
// crash the host reads as instability.
func autoSealEvidence(
	tp policy.TransparencyPolicy,
	session string,
	plans []plan.Document,
	posture []byte,
	logger *slog.Logger,
) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("evidence auto-seal panicked", "panic", r)
		}
	}()

	if !auditDestinationIsDir(tp.AuditDestination) {
		logger.Warn("evidence_dir is set but audit_sink is not a directory; skipping auto-seal",
			"hint", "point audit_sink at a directory so each session has its own file to bundle")
		return
	}
	if err := os.MkdirAll(tp.EvidenceDir, 0o700); err != nil {
		logger.Error("evidence auto-seal: create evidence dir", "error", err)
		return
	}

	var extra []evidence.Source
	for _, d := range plans {
		if b, err := json.MarshalIndent(d, "", "  "); err == nil {
			extra = append(extra, evidence.Source{
				ArchivePath: "plans/plan-" + shortPlanID(d.PlanID) + ".json", Bytes: b,
			})
		}
	}
	if len(posture) > 0 {
		extra = append(extra, evidence.Source{ArchivePath: "posture-end.json", Bytes: posture})
	}
	extra = append(extra, journeySources(tp.EvidenceDir, session)...)

	outPath := filepath.Join(tp.EvidenceDir, "session-"+session+".evidence.zip")
	man, err := BundleEvidence(tp.AuditDestination, session, tp.RecordingDir, outPath,
		os.Getenv("WINDOWS_MCP_EVIDENCE_KEY_FILE"), extra...)
	if err != nil {
		logger.Error("evidence auto-seal failed", "error", err)
		return
	}
	logger.Info("session evidence sealed", "path", outPath, "files", len(man.Files), "signed", man.Signed)
}

func shortPlanID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	if id == "" {
		return "unhashed"
	}
	return id
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

// journeySources collects a session's journey artifacts: the OTLP/JSON run
// records and the images their captures wrote. Both are hashed into the bundle
// manifest by the same sealer as everything else, so a journey's evidence is
// covered by the same signature and the same audit-head cross-check — nothing new
// is needed to verify it, because the members are files and the bundle already
// proves files.
//
// Run records are matched by the session stamp so a directory holding several
// sessions bundles only this one's. Images are not stamped — they are numbered in
// capture order — so a shared evidence directory across sessions would over-collect;
// the per-session subdirectory layout the runner writes avoids that.
func journeySources(evidenceDir, session string) []evidence.Source {
	if evidenceDir == "" {
		return nil
	}
	var out []evidence.Source
	records, _ := filepath.Glob(filepath.Join(evidenceDir, "journeys", "*-"+session+".otlp.json"))
	for _, r := range records {
		out = append(out, evidence.Source{ArchivePath: "journeys/" + filepath.Base(r), FilePath: r})
	}
	images, _ := filepath.Glob(filepath.Join(evidenceDir, "evidence", "*.png"))
	for _, img := range images {
		out = append(out, evidence.Source{ArchivePath: "evidence/" + filepath.Base(img), FilePath: img})
	}
	return out
}

// dedupeSources drops repeated archive paths, keeping the first. Sealing refuses
// a duplicate member, and the journey artifacts can legitimately be offered twice
// when an evidence directory is also the audit directory.
func dedupeSources(in []evidence.Source) []evidence.Source {
	seen := make(map[string]bool, len(in))
	out := make([]evidence.Source, 0, len(in))
	for _, s := range in {
		if seen[s.ArchivePath] {
			continue
		}
		seen[s.ArchivePath] = true
		out = append(out, s)
	}
	return out
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
