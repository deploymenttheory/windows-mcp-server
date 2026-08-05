//go:build windows && (amd64 || arm64)

package windows

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
)

// Evidence capture used to run, be audited, and return an image to the model —
// and write nothing to disk, so the durable record of a run contained no pictures
// of it. This is the sink that fixes that.
//
// Writing is conditional on a directory being configured. A run with nowhere to
// put images still captures the snapshot text and records the capture, rather
// than failing: a missing output directory is a configuration choice, not a test
// failure.

// EvidenceArtifact is one captured image on disk.
type EvidenceArtifact struct {
	// Label is the caption from the journey document. It is what expected_evidence
	// is matched against after a run.
	Label string
	// Path is relative to the evidence directory, and is also the path the artifact
	// takes inside an evidence bundle.
	Path   string
	SHA256 string
	Width  int
	Height int
}

// EvidenceSink is the optional interface a dependency set implements to persist
// captured evidence. It is an optional interface for the same reason ReadRegister
// is: adding to ToolDependencies would break every other implementation.
type EvidenceSink interface {
	// WriteEvidence persists one capture and returns what was written. It reports
	// ok=false when no evidence directory is configured, which is not an error.
	WriteEvidence(label string, png []byte, width, height int) (EvidenceArtifact, bool, error)
	// CapturedEvidence returns everything written this run, in capture order.
	CapturedEvidence() []EvidenceArtifact
}

// evidenceWriter persists captures under a directory, numbering them in capture
// order so images sort the way the run ran.
type evidenceWriter struct {
	dir string

	mu        sync.Mutex
	artifacts []EvidenceArtifact
}

// WithEvidenceDir turns on screenshot persistence. Returns the receiver for
// chaining.
func (d *BaseDeps) WithEvidenceDir(dir string) *BaseDeps {
	if dir != "" {
		d.evidence = &evidenceWriter{dir: dir}
	}
	return d
}

// WriteEvidence implements EvidenceSink.
func (d *BaseDeps) WriteEvidence(label string, png []byte, width, height int) (EvidenceArtifact, bool, error) {
	if d.evidence == nil {
		return EvidenceArtifact{}, false, nil
	}
	art, err := d.evidence.write(label, png, width, height)
	return art, err == nil, err
}

// CapturedEvidence implements EvidenceSink.
func (d *BaseDeps) CapturedEvidence() []EvidenceArtifact {
	if d.evidence == nil {
		return nil
	}
	return d.evidence.captured()
}

func (w *evidenceWriter) write(label string, png []byte, width, height int) (EvidenceArtifact, error) {
	w.mu.Lock()
	ordinal := len(w.artifacts) + 1
	w.mu.Unlock()

	if err := os.MkdirAll(w.dir, 0o700); err != nil {
		return EvidenceArtifact{}, fmt.Errorf("evidence dir: %w", err)
	}
	name := fmt.Sprintf("%02d-%s.png", ordinal, slugify(label))
	sum := sha256.Sum256(png)
	if err := os.WriteFile(filepath.Join(w.dir, name), png, 0o600); err != nil {
		return EvidenceArtifact{}, fmt.Errorf("write evidence %s: %w", name, err)
	}

	art := EvidenceArtifact{
		Label: label, Path: name, SHA256: hex.EncodeToString(sum[:]),
		Width: width, Height: height,
	}
	w.mu.Lock()
	w.artifacts = append(w.artifacts, art)
	w.mu.Unlock()
	return art, nil
}

func (w *evidenceWriter) captured() []EvidenceArtifact {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]EvidenceArtifact(nil), w.artifacts...)
}

// slugify renders a caption as a filename component: lower case, with every run
// of anything else collapsed to a single hyphen. It is not reversible and does
// not need to be — the label itself is recorded in the run record; this only has
// to be stable, safe on Windows, and readable in a directory listing.
func slugify(label string) string {
	var b strings.Builder
	lastHyphen := true // suppress a leading hyphen
	for _, r := range strings.ToLower(strings.TrimSpace(label)) {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
			lastHyphen = false
		case !lastHyphen:
			b.WriteByte('-')
			lastHyphen = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "evidence"
	}
	const maxSlug = 60
	if len(out) > maxSlug {
		out = strings.Trim(out[:maxSlug], "-")
	}
	return out
}
