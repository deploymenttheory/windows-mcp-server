//go:build windows && (amd64 || arm64)

package windows

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"claim submitted":          "claim-submitted",
		"Notepad opened!":          "notepad-opened",
		"  spaced  out  ":          "spaced-out",
		"£126.40 total":            "126-40-total",
		"":                         "evidence",
		"---":                      "evidence",
		"a/b\\c:d*e?f\"g<h>i|j":    "a-b-c-d-e-f-g-h-i-j",
		"Ünïcodé":                  "ünïcodé",
	}
	for in, want := range cases {
		if got := slugify(in); got != want {
			t.Errorf("slugify(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSlugifyIsSafeAsAWindowsFilename: a caption is author-supplied text, and it
// becomes a path.
func TestSlugifyIsSafeAsAWindowsFilename(t *testing.T) {
	for _, bad := range []string{`..\..\escape`, "con", `a:b`, "trailing.", "with space"} {
		got := slugify(bad)
		for _, r := range `\/:*?"<>|` {
			if containsRune(got, r) {
				t.Errorf("slugify(%q) = %q, which contains the reserved character %q", bad, got, r)
			}
		}
		if got == "" {
			t.Errorf("slugify(%q) produced an empty name", bad)
		}
	}
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}

// TestWriteEvidencePersistsAndHashes is the fix for the documented gap: captures
// used to return an image to the model and write nothing, so the durable record
// of a run contained no pictures of it.
func TestWriteEvidencePersistsAndHashes(t *testing.T) {
	dir := t.TempDir()
	deps := NewBaseDeps(nil, nil, nil).WithEvidenceDir(dir)

	png := []byte("not really a png, but bytes are bytes")
	art, written, err := deps.WriteEvidence("claim submitted", png, 1920, 1080)
	if err != nil || !written {
		t.Fatalf("write: %v (written=%v)", err, written)
	}

	if art.Path != "01-claim-submitted.png" {
		t.Errorf("path = %q, want it numbered in capture order and slugified", art.Path)
	}
	sum := sha256.Sum256(png)
	if art.SHA256 != hex.EncodeToString(sum[:]) {
		t.Error("the recorded digest should be of the bytes written")
	}
	if art.Width != 1920 || art.Height != 1080 {
		t.Errorf("dimensions not carried: %+v", art)
	}

	onDisk, err := os.ReadFile(filepath.Join(dir, art.Path))
	if err != nil {
		t.Fatalf("the image should be on disk: %v", err)
	}
	if string(onDisk) != string(png) {
		t.Error("the file should hold exactly what was captured")
	}
}

// TestEvidenceIsNumberedInCaptureOrder: images should sort the way the run ran,
// which is what makes a directory listing readable as a sequence.
func TestEvidenceIsNumberedInCaptureOrder(t *testing.T) {
	deps := NewBaseDeps(nil, nil, nil).WithEvidenceDir(t.TempDir())
	for _, label := range []string{"first", "second", "third"} {
		if _, _, err := deps.WriteEvidence(label, []byte(label), 10, 10); err != nil {
			t.Fatal(err)
		}
	}
	got := deps.CapturedEvidence()
	want := []string{"01-first.png", "02-second.png", "03-third.png"}
	if len(got) != len(want) {
		t.Fatalf("captured %d artifacts, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Path != w {
			t.Errorf("artifact %d path = %q, want %q", i, got[i].Path, w)
		}
	}
}

// TestNoEvidenceDirIsNotAnError: a run with nowhere to write images still
// captures and records; a missing output directory is a configuration choice,
// not a test failure.
func TestNoEvidenceDirIsNotAnError(t *testing.T) {
	deps := NewBaseDeps(nil, nil, nil)
	art, written, err := deps.WriteEvidence("x", []byte("y"), 1, 1)
	if err != nil {
		t.Errorf("no evidence dir should not be an error, got %v", err)
	}
	if written {
		t.Error("nothing should be reported as written")
	}
	if art.Path != "" {
		t.Error("no artifact should be described")
	}
	if deps.CapturedEvidence() != nil {
		t.Error("nothing should be captured")
	}
}

// TestAssertionRegisterRoundTrips pins the side channel the run record reads the
// observed value through.
func TestAssertionRegisterRoundTrips(t *testing.T) {
	deps := NewBaseDeps(nil, nil, nil)
	if _, set := deps.LastAssertion(); set {
		t.Error("nothing should be recorded before an assertion runs")
	}
	want := AssertionRecord{
		Subject: "element.value", Operator: "is",
		Expected: "£126.40", Observed: `"£12.40"`, Passed: false, Polls: 3, Timeout: 15,
	}
	deps.RecordAssertion(want)
	got, set := deps.LastAssertion()
	if !set || got != want {
		t.Errorf("LastAssertion() = %+v (set=%v), want %+v", got, set, want)
	}
}

func TestReadRegisterRoundTrips(t *testing.T) {
	deps := NewBaseDeps(nil, nil, nil)
	if _, set := deps.LastRead(); set {
		t.Error("nothing should be readable before a read step runs")
	}
	deps.SetLastRead("EXP-447123")
	if got, set := deps.LastRead(); !set || got != "EXP-447123" {
		t.Errorf("LastRead() = %q (set=%v)", got, set)
	}
}
