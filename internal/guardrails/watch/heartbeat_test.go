package watch

import (
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
	"sync/atomic"

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

// TestWatchdogKeepsWatchingAfterAGap is a regression test for a watchdog that
// disabled itself. It returned after reporting one gap -- so when the trigger is
// disarmed, which is the default, onGap returns normally and the goroutine simply
// ended: the second stall and every one after it went unreported for the rest of
// the session. It is the same rule the monitor loop keeps with
// MonitorConfig.Stopped.
func TestWatchdogKeepsWatchingAfterAGap(t *testing.T) {
	h := NewHeartbeat(audit.NewAuditLog(&memDest{}))
	var now atomic.Int64
	now.Store(time.Now().UnixNano())
	h.clock = func() time.Time { return time.Unix(0, now.Load()) }
	h.started = h.clock()

	var gaps atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.StartWatchdog(ctx, 2*time.Second, func(string) { gaps.Add(1) })

	// Stall: no beats at all. The first gap is reported.
	now.Add(int64(10 * time.Second))
	if !waitFor(t, 3*time.Second, func() bool { return gaps.Load() >= 1 }) {
		t.Fatal("the first heartbeat gap was never reported")
	}

	// Beats resume, then stall again. A watchdog that returned after the first
	// report would never see this one.
	_ = h.Beat(ctx)
	if !waitFor(t, 3*time.Second, func() bool { return !h.GapExceeded(2 * time.Second) }) {
		t.Fatal("beats did not resume")
	}
	now.Add(int64(10 * time.Second))
	if !waitFor(t, 3*time.Second, func() bool { return gaps.Load() >= 2 }) {
		t.Error("a second stall must be reported; the watchdog must not stop after the first")
	}
}

// TestGapBeforeAnyBeatIsDetected covers the other half: a monitor that dies
// before its first tick. "No beat has ever happened" used to be
// indistinguishable from "healthy", so the watchdog waited forever on exactly
// the failure it exists to catch.
func TestGapBeforeAnyBeatIsDetected(t *testing.T) {
	h := NewHeartbeat(audit.NewAuditLog(&memDest{}))
	base := time.Now()
	h.started = base
	h.clock = func() time.Time { return base.Add(time.Minute) }

	if !h.GapExceeded(5 * time.Second) {
		t.Error("a heartbeat that never beat must count as a gap once maxAge has passed")
	}
}
