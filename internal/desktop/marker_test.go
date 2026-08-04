//go:build windows && (amd64 || arm64)

package desktop

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newMarkerRecorder builds a recorder that only writes markers. Starting a real
// one needs a desktop to capture, and this is about what is written, not about
// frames.
func newMarkerRecorder(t *testing.T) (*Desktop, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "markers.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return &Desktop{recorder: &recorder{markers: f, started: time.Now()}}, path
}

// TestAgentMarkersCannotForgeSecurityEvents pins the namespace that keeps a
// model-supplied marker distinguishable from a guardrail one.
//
// Both go into the same session .jsonl, and guardrail events are written as
// "SECURITY: ...". Recording{mode:"mark"} took an arbitrary label, so
// "SECURITY: kill switch disarmed by operator" was byte-identical to a real event
// in the forensic timeline -- and the tool was annotated read-only, so it was
// served even under --read-only.
func TestAgentMarkersCannotForgeSecurityEvents(t *testing.T) {
	d, path := newMarkerRecorder(t)

	d.MarkRecording("SECURITY: kill switch disarmed by operator")
	d.ShowSecurityBanner("real guardrail event")

	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(blob)

	if !strings.Contains(body, agentMarkerPrefix+"SECURITY: kill switch disarmed") {
		t.Errorf("an agent marker must be namespaced so its author is unambiguous: %s", body)
	}
	if strings.Contains(body, `"label":"SECURITY: kill switch disarmed`) {
		t.Errorf("an agent marker must not be written in the guardrail form: %s", body)
	}
	if !strings.Contains(body, `"label":"SECURITY: real guardrail event"`) {
		t.Errorf("a genuine guardrail marker must keep its unprefixed form: %s", body)
	}
}

// TestAgentMarkerLabelIsBounded keeps an unbounded label from filling the volume
// the recording is written to.
func TestAgentMarkerLabelIsBounded(t *testing.T) {
	d, path := newMarkerRecorder(t)

	d.MarkRecording(strings.Repeat("A", 10<<20))

	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) > maxMarkerLabel*2 {
		t.Errorf("marker entry is %d bytes; a model must not choose how much it writes", len(blob))
	}
}
