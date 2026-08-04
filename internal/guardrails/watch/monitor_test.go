package watch

import (
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/contain"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/signals"

	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// errVerify is a static error for the verifier-failure paths (err113).
var errVerify = errors.New("verifier failed")

// driftDecision is a decision that no longer admits, to drive posture drift.
func driftDecision() signals.Decision {
	return signals.Decision{Admit: false, Reasons: []string{"secure-boot=fail"}}
}

// waitFor polls until cond holds or the deadline passes. Keeps the monitor tests
// fast without sleeping for a fixed worst case.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// TestMonitorReportOnlyTripKeepsMonitoring is the central regression guard: when
// a trigger is disarmed its trip function only reports, so the monitor must keep
// evaluating. Before per-trigger gating the loop returned on the first trip,
// which would have made disarming one trigger silently disable all monitoring.
func TestMonitorReportOnlyTripKeepsMonitoring(t *testing.T) {
	var trips, evals atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	StartMonitor(ctx, MonitorConfig{
		Interval: 10 * time.Millisecond,
		Evaluate: func(context.Context) signals.Decision {
			evals.Add(1)
			return driftDecision()
		},
		TripPostureDrift: func(string) { trips.Add(1) },
		Stopped:          func() bool { return false }, // report-only: never stops
	})

	if !waitFor(t, 2*time.Second, func() bool { return trips.Load() >= 2 }) {
		t.Fatalf("monitor stopped after a report-only trip: trips=%d evals=%d",
			trips.Load(), evals.Load())
	}
}

// TestMonitorExitsWhenStopped is the other half: a real trip sets the kill
// switch, Stopped reports true, and the loop must exit rather than keep
// re-tripping a server that is already tearing down.
func TestMonitorExitsWhenStopped(t *testing.T) {
	var trips atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kill := contain.NewKillSwitch(nil)
	StartMonitor(ctx, MonitorConfig{
		Interval: 10 * time.Millisecond,
		Evaluate: func(context.Context) signals.Decision { return driftDecision() },
		TripPostureDrift: func(reason string) {
			trips.Add(1)
			kill.Trip(reason)
		},
		Stopped: func() bool { tripped, _ := kill.Tripped(); return tripped },
	})

	if !waitFor(t, 2*time.Second, func() bool { return trips.Load() >= 1 }) {
		t.Fatal("monitor never tripped")
	}
	time.Sleep(100 * time.Millisecond) // several further ticks would have elapsed
	if n := trips.Load(); n != 1 {
		t.Errorf("monitor must exit after a real trip, got %d trips", n)
	}
}

// TestMonitorVerifierUsesItsOwnTrip proves heartbeat and rug-pull arm
// independently: only the failing verifier's own trip function fires.
func TestMonitorVerifierUsesItsOwnTrip(t *testing.T) {
	var heartbeatTrips, rugpullTrips atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	StartMonitor(ctx, MonitorConfig{
		Interval: 10 * time.Millisecond,
		Verify: []VerifyFunc{
			{
				Name: "heartbeat",
				Run:  func(context.Context) error { return nil },
				Trip: func(string) { heartbeatTrips.Add(1) },
			},
			{
				Name: "rug-pull",
				Run:  func(context.Context) error { return errVerify },
				Trip: func(string) { rugpullTrips.Add(1) },
			},
		},
		Stopped: func() bool { return false },
	})

	if !waitFor(t, 2*time.Second, func() bool { return rugpullTrips.Load() >= 1 }) {
		t.Fatal("failing verifier never fired its trip")
	}
	if n := heartbeatTrips.Load(); n != 0 {
		t.Errorf("passing verifier must not trip, got %d", n)
	}
}

// TestMonitorSentinelReportedOnce guards against audit-log spam: the sentinel
// file stays on disk, so a report-only sentinel trigger must not re-fire on
// every tick.
func TestMonitorSentinelReportedOnce(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "kill"), []byte("stop"), 0o600); err != nil {
		t.Fatal(err)
	}

	var trips atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	StartMonitor(ctx, MonitorConfig{
		Interval:     10 * time.Millisecond,
		ControlDir:   dir,
		TripSentinel: func(string) { trips.Add(1) },
		Stopped:      func() bool { return false },
	})

	if !waitFor(t, 2*time.Second, func() bool { return trips.Load() >= 1 }) {
		t.Fatal("sentinel file was never detected")
	}
	time.Sleep(100 * time.Millisecond) // many further ticks
	if n := trips.Load(); n != 1 {
		t.Errorf("sentinel must be reported once, got %d", n)
	}
}

// TestSentinelRequiresTheSessionToken is a regression test for the one
// authoritative kill trigger an agent could fire by itself. The sentinel was
// authenticated by its own existence, so a single file write -- via the
// FileSystem tool, or any PowerShell redirect, which protected paths do not
// cover -- ran the containment ladder, including network isolation and shutdown
// when the policy armed them.
func TestSentinelRequiresTheSessionToken(t *testing.T) {
	cases := []struct {
		name          string
		token         string
		contents      string
		wantAuthentic bool
	}{
		{"matching token trips", "secret-token", "secret-token", true},
		{"trailing whitespace is tolerated", "secret-token", "secret-token\r\n", true},
		{"agent-written content is refused", "secret-token", "kill", false},
		{"empty file is refused", "secret-token", "", false},
		{"wrong token is refused", "secret-token", "guessed", false},
		{"no token configured falls back to presence", "", "anything", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "kill"), []byte(tc.contents), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := MonitorConfig{ControlDir: dir, SentinelToken: tc.token}
			authentic, present := cfg.readSentinel()
			if !present {
				t.Fatal("the sentinel file exists and must be reported present")
			}
			if authentic != tc.wantAuthentic {
				t.Errorf("authentic = %v, want %v", authentic, tc.wantAuthentic)
			}
		})
	}
}

// TestAbsentSentinelIsNotPresent keeps the common case -- no file -- from
// reading as a rejected trip.
func TestAbsentSentinelIsNotPresent(t *testing.T) {
	cfg := MonitorConfig{ControlDir: t.TempDir(), SentinelToken: "t"}
	if authentic, present := cfg.readSentinel(); present || authentic {
		t.Errorf("no sentinel file should be neither present nor authentic, got present=%v authentic=%v",
			present, authentic)
	}
}
