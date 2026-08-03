//go:build windows && (amd64 || arm64)

package winmcp

import (
	"testing"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
)

type fakeAnchorWriter struct{ heads []string }

func (f *fakeAnchorWriter) publish(_ uint64, head string) { f.heads = append(f.heads, head) }

// TestAnchorOnceOnlyAnchorsOnActivity pins the guard that stops an idle server
// growing its own chain: an anchor advances the head, so without the guard every
// subsequent tick would see a "new" head and anchor forever.
func TestAnchorOnceOnlyAnchorsOnActivity(t *testing.T) {
	log := audit.NewAuditLog(nil) // nil dest: Head/Append still advance the chain
	log.Append("server.start", nil)

	w := &fakeAnchorWriter{}
	last := ""

	last = anchorOnce(log, last, w)
	if len(w.heads) != 1 {
		t.Fatalf("first tick after activity should anchor once, got %d", len(w.heads))
	}

	last = anchorOnce(log, last, w)
	if len(w.heads) != 1 {
		t.Errorf("an idle tick must not anchor, got %d publishes", len(w.heads))
	}

	log.Append("tool.call", nil)
	last = anchorOnce(log, last, w)
	if len(w.heads) != 2 {
		t.Errorf("activity since the last anchor should anchor again, got %d", len(w.heads))
	}
	_ = last

	// Each publish names a distinct head.
	if w.heads[0] == w.heads[1] {
		t.Error("the two anchors should name different heads")
	}
}

// TestAnchorOnceNilWriterStillChains covers chain-only anchoring: when the off-box
// writer could not be opened, an audit.anchor entry is still appended.
func TestAnchorOnceNilWriterStillChains(t *testing.T) {
	log := audit.NewAuditLog(nil)
	log.Append("server.start", nil)
	before, _ := log.Head()
	anchorOnce(log, "", nil)
	after, _ := log.Head()
	if after != before+1 {
		t.Errorf("chain-only anchor should append one entry: before=%d after=%d", before, after)
	}
}
