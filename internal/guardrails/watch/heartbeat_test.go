package watch

import (
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"

	"context"
	"testing"
	"time"
)

func TestHeartbeatBeatsChainAndCount(t *testing.T) {
	dest := &memDest{}
	hb := NewHeartbeat(audit.NewAuditLog(dest))
	for i := 0; i < 3; i++ {
		if err := hb.Beat(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if c, _ := hb.Snapshot(); c != 3 {
		t.Errorf("beat count = %d, want 3", c)
	}
	if err := audit.VerifyChain(dest.entries); err != nil {
		t.Errorf("heartbeat entries should form a valid chain: %v", err)
	}
	for _, e := range dest.entries {
		if e.Event != "heartbeat" {
			t.Errorf("unexpected audit event %q", e.Event)
		}
	}
}

func TestHeartbeatGapExceeded(t *testing.T) {
	dest := &memDest{}
	now := time.Unix(1_700_000_000, 0)
	hb := NewHeartbeat(audit.NewAuditLog(dest))
	hb.clock = func() time.Time { return now }

	if hb.GapExceeded(time.Minute) {
		t.Error("no beat yet → no gap")
	}
	hb.Beat(context.Background())
	if hb.GapExceeded(time.Minute) {
		t.Error("just beat → no gap")
	}
	now = now.Add(2 * time.Minute)
	if !hb.GapExceeded(time.Minute) {
		t.Error("2m elapsed with 1m maxAge → gap")
	}
	if _, age := hb.Snapshot(); age != 2*time.Minute {
		t.Errorf("snapshot age = %s, want 2m", age)
	}
}
