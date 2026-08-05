//go:build windows && (amd64 || arm64)

package winmcp

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/evidence"
	"github.com/deploymenttheory/windows-mcp-server/pkg/windows"
)

// TestReconcileEvidenceChecksTheRunNotTheDocument is the point of moving the
// expected_evidence check after the run. The static check only says some step
// claims it will capture the label — which a run that fail-stopped at step 2
// satisfies without ever having produced it.
func TestReconcileEvidenceChecksTheRunNotTheDocument(t *testing.T) {
	expected := []string{"notepad opened", "text typed"}

	// A run that fail-stopped after the first capture.
	captured, missing := reconcileEvidence(expected, []windows.EvidenceArtifact{
		{Label: "notepad opened", Path: "01-notepad-opened.png"},
	})
	if !slices.Equal(captured, []string{"notepad opened"}) {
		t.Errorf("captured = %v", captured)
	}
	if !slices.Equal(missing, []string{"text typed"}) {
		t.Errorf("missing = %v, want the label the run never produced", missing)
	}

	// A complete run.
	_, missing = reconcileEvidence(expected, []windows.EvidenceArtifact{
		{Label: "notepad opened"}, {Label: "text typed"},
	})
	if len(missing) != 0 {
		t.Errorf("a complete run should be missing nothing, got %v", missing)
	}

	// A journey expecting nothing is satisfied by anything.
	if _, missing := reconcileEvidence(nil, nil); len(missing) != 0 {
		t.Errorf("no expectation should mean nothing missing, got %v", missing)
	}
}

func TestJourneyStatusMessage(t *testing.T) {
	if got := journeyStatusMessage(true, 0, nil); got != "passed" {
		t.Errorf("passed run message = %q", got)
	}
	if got := journeyStatusMessage(false, 2, nil); got != "2 step(s) failed" {
		t.Errorf("failed run message = %q", got)
	}
	got := journeyStatusMessage(false, 0, []string{"text typed"})
	if got != "expected evidence never captured: text typed" {
		t.Errorf("evidence-only failure message = %q", got)
	}
}

// TestJourneySourcesCollectsThisSessionsArtifacts: a directory holding several
// sessions must bundle only the one being sealed.
func TestJourneySourcesCollectsThisSessionsArtifacts(t *testing.T) {
	root := t.TempDir()
	mkdir(t, filepath.Join(root, "journeys"))
	mkdir(t, filepath.Join(root, "evidence"))

	write(t, filepath.Join(root, "journeys", "notepad-smoke-20260805-141233.otlp.json"), "{}")
	write(t, filepath.Join(root, "journeys", "other-20260101-000000.otlp.json"), "{}")
	write(t, filepath.Join(root, "evidence", "01-notepad-opened.png"), "png")

	got := journeySources(root, "20260805-141233")

	var paths []string
	for _, s := range got {
		paths = append(paths, s.ArchivePath)
	}
	slices.Sort(paths)
	want := []string{"evidence/01-notepad-opened.png", "journeys/notepad-smoke-20260805-141233.otlp.json"}
	if !slices.Equal(paths, want) {
		t.Errorf("collected %v, want %v — a different session's run record must not be bundled", paths, want)
	}
}

func TestJourneySourcesWithNoEvidenceDir(t *testing.T) {
	if got := journeySources("", "s"); got != nil {
		t.Errorf("no evidence dir should collect nothing, got %v", got)
	}
}

// TestDedupeSourcesKeepsTheFirst: sealing refuses a duplicate member, and the
// journey artifacts can legitimately be offered twice when the evidence
// directory is also the audit directory.
func TestDedupeSourcesKeepsTheFirst(t *testing.T) {
	in := []evidence.Source{
		{ArchivePath: "a.json", Bytes: []byte("first")},
		{ArchivePath: "b.json", Bytes: []byte("b")},
		{ArchivePath: "a.json", Bytes: []byte("second")},
	}
	got := dedupeSources(in)
	if len(got) != 2 {
		t.Fatalf("want 2 sources, got %d", len(got))
	}
	if string(got[0].Bytes) != "first" {
		t.Errorf("the first occurrence should win, got %q", got[0].Bytes)
	}
}

// TestJourneyVerdictsReachTheBundle: a bundle sealed from a journey run used to
// carry the plan.* entry for each step and no record of whether the journey
// passed — the one line a reviewer opens the file to read.
func TestJourneyVerdictsReachTheBundle(t *testing.T) {
	for _, event := range []string{"journey.started", "journey.finished"} {
		if !isVerdict(event) {
			t.Errorf("%s should be extracted into verdicts.json", event)
		}
	}
	if isVerdict("tool.call") {
		t.Error("an ordinary tool call is not a verdict")
	}
}

func TestSlugForFile(t *testing.T) {
	cases := map[string]string{
		"notepad-smoke":   "notepad-smoke",
		"Expenses Submit": "expenses-submit",
		"a/b":             "a-b",
		"":                "journey",
		"!!!":             "journey",
	}
	for in, want := range cases {
		if got := slugForFile(in); got != want {
			t.Errorf("slugForFile(%q) = %q, want %q", in, got, want)
		}
	}
}

func mkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
