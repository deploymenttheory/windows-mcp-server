package guardrails

import (
	"context"
	"testing"
	"time"
)

func TestHeartbeatBeatsChainAndCount(t *testing.T) {
	sink := &memSink{}
	hb := NewHeartbeat(NewAuditLog(sink))
	for i := 0; i < 3; i++ {
		if err := hb.Beat(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if c, _ := hb.Snapshot(); c != 3 {
		t.Errorf("beat count = %d, want 3", c)
	}
	if err := VerifyChain(sink.entries); err != nil {
		t.Errorf("heartbeat entries should form a valid chain: %v", err)
	}
	for _, e := range sink.entries {
		if e.Event != "heartbeat" {
			t.Errorf("unexpected audit event %q", e.Event)
		}
	}
}

func TestHeartbeatGapExceeded(t *testing.T) {
	sink := &memSink{}
	now := time.Unix(1_700_000_000, 0)
	hb := NewHeartbeat(NewAuditLog(sink))
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
