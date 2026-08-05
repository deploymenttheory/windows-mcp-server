//go:build windows && (amd64 || arm64)

package winmcp

import (
	"archive/zip"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/evidence"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/plan"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/policy"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func writeSession(t *testing.T, dir, session string) {
	t.Helper()
	dest, err := audit.OpenDestination(dir, session)
	if err != nil {
		t.Fatal(err)
	}
	log := audit.NewAuditLog(dest)
	log.Append("server.started", map[string]any{"session": session})
	log.Append("policy.decided", map[string]any{"verdict": "deny"})
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
}

func zipNames(t *testing.T, path string) []string {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = zr.Close() }()
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	return names
}

func TestAutoSealEvidenceBundlesPlansAndPosture(t *testing.T) {
	t.Setenv("WINDOWS_MCP_EVIDENCE_KEY_FILE", "") // force unsigned, deterministic

	auditDir := t.TempDir()
	evDir := t.TempDir()
	writeSession(t, auditDir, "20260803-120000")

	doc, _ := plan.Document{Version: plan.SchemaVersion, Steps: []plan.Step{{Tool: "Snapshot"}}}.WithID()
	posture := []byte(`{"admit":true,"killed":false}`)

	tp := policy.TransparencyPolicy{AuditDestination: auditDir, EvidenceDir: evDir}
	autoSealEvidence(tp, "20260803-120000", []plan.Document{doc}, posture, nil, discardLogger())

	bundle := filepath.Join(evDir, "session-20260803-120000.evidence.zip")
	rep, err := evidence.Verify(bundle, "")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !rep.OK() {
		t.Fatalf("an auto-sealed bundle should verify: %s", rep)
	}

	names := strings.Join(zipNames(t, bundle), "\n")
	for _, want := range []string{"posture-end.json", "verdicts.json", "plans/plan-", "audit/session-20260803-120000.audit.jsonl"} {
		if !strings.Contains(names, want) {
			t.Errorf("bundle should contain %q; members:\n%s", want, names)
		}
	}
}

func TestAutoSealSkipsWhenAuditSinkNotDirectory(t *testing.T) {
	evDir := t.TempDir()
	tp := policy.TransparencyPolicy{AuditDestination: "stderr", EvidenceDir: evDir}
	autoSealEvidence(tp, "x", nil, nil, nil, discardLogger())

	if entries, _ := os.ReadDir(evDir); len(entries) != 0 {
		t.Error("no bundle should be written when the audit dest is not a directory")
	}
}
