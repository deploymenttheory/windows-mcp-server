// Package watch is continuous verification: the heartbeat that proves liveness,
// the rug-pull detector that fingerprints the served manifests, and the monitor
// loop that drives both plus the background signal refresh.
//
// Everything here reports; nothing here contains. Each detector is handed a trip
// function by the caller, already gated on the policy, so a trigger an operator
// left off is still detected, logged and chained. Transparency is never
// conditional on containment.
package watch

import (
	"context"
	"sync"
	"time"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
)

// Heartbeat emits periodic entries into the hash-chained audit log so that a
// stall or a gap in agent/session activity is detectable — both by an external
// watcher polling the status snapshot and by an in-process watchdog. Beats are
// produced by the in-flight monitor tick; gap enforcement is deliberately
// independent of that loop so a stalled monitor is still caught.
type Heartbeat struct {
	audit *audit.AuditLog
	clock func() time.Time

	mu    sync.Mutex
	count uint64
	last  time.Time
	// started is when the heartbeat was created, used as the reference point
	// before the first beat so "never beat" is measurable rather than invisible.
	started time.Time
}

// NewHeartbeat builds a heartbeat over the audit log.
func NewHeartbeat(audit *audit.AuditLog) *Heartbeat {
	return &Heartbeat{audit: audit, clock: time.Now, started: time.Now()}
}

// Beat appends one heartbeat entry to the audit chain. It is registered as a
// monitor verifier so it fires on every in-flight tick.
func (h *Heartbeat) Beat(ctx context.Context) error {
	h.mu.Lock()
	h.count++
	c := h.count
	h.last = h.clock()
	h.mu.Unlock()
	_, err := h.audit.Append("heartbeat", map[string]any{"beat": c})
	return err
}

// Snapshot returns the beat count and the age of the last beat, for the status
// surface.
func (h *Heartbeat) Snapshot() (count uint64, age time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.last.IsZero() {
		return h.count, 0
	}
	return h.count, h.clock().Sub(h.last)
}

// GapExceeded reports whether more than maxAge has elapsed since the last beat.
//
// Before any beat has occurred it measures from when the heartbeat was created,
// not from the zero time. "No beat has ever happened" used to be indistinguishable
// from "healthy", so a monitor goroutine that died before its first tick left the
// watchdog waiting forever — the one failure the watchdog exists to catch.
//
// Pure and clock-injectable for tests.
func (h *Heartbeat) GapExceeded(maxAge time.Duration) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	since := h.last
	if since.IsZero() {
		since = h.started
	}
	if since.IsZero() {
		return false
	}
	return h.clock().Sub(since) > maxAge
}

// StartWatchdog runs an independent goroutine (separate from the in-flight
// monitor that produces beats) that trips onGap if beats stall for longer than
// maxAge. It stops when ctx is cancelled. Checking on its own ticker means a
// hung monitor loop is still detected; a wholly-hung process is covered instead
// by external status polling.
func (h *Heartbeat) StartWatchdog(ctx context.Context, maxAge time.Duration, onGap func(reason string)) {
	if maxAge <= 0 || onGap == nil {
		return
	}
	check := maxAge / 2
	if check < time.Second {
		check = time.Second
	}
	go func() {
		t := time.NewTicker(check)
		defer t.Stop()
		// reported suppresses repeat notifications for one continuous stall.
		// It is re-armed by the beat counter advancing rather than by observing a
		// healthy tick, so re-arming does not depend on the watchdog happening to
		// look during the recovery window.
		var reported bool
		lastCount, _ := h.Snapshot()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if count, _ := h.Snapshot(); count != lastCount {
					lastCount = count
					reported = false
				}
				if h.GapExceeded(maxAge) && !reported {
					// Report once per stall, then keep watching. Returning here
					// meant a report-only gap — the default, since the trigger is
					// disarmed unless a policy arms it — silently ended gap
					// detection for the rest of the session, so the second stall
					// and every one after it went unnoticed. It is the same rule
					// the monitor loop keeps with MonitorConfig.Stopped.
					reported = true
					onGap("heartbeat gap: no beat within " + maxAge.String())
				}
			}
		}
	}()
}
