package guardrails

import (
	"context"
	"sync"
	"time"
)

// Heartbeat emits periodic entries into the hash-chained audit log so that a
// stall or a gap in agent/session activity is detectable — both by an external
// watcher polling the status snapshot and by an in-process watchdog. Beats are
// produced by the in-flight monitor tick; gap enforcement is deliberately
// independent of that loop so a stalled monitor is still caught.
type Heartbeat struct {
	audit *AuditLog
	clock func() time.Time

	mu    sync.Mutex
	count uint64
	last  time.Time
}

// NewHeartbeat builds a heartbeat over the audit log.
func NewHeartbeat(audit *AuditLog) *Heartbeat {
	return &Heartbeat{audit: audit, clock: time.Now}
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

// GapExceeded reports whether more than maxAge has elapsed since the last beat
// (a beat must have occurred at least once). Pure and clock-injectable for tests.
func (h *Heartbeat) GapExceeded(maxAge time.Duration) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.last.IsZero() {
		return false
	}
	return h.clock().Sub(h.last) > maxAge
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
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if h.GapExceeded(maxAge) {
					onGap("heartbeat gap: no beat within " + maxAge.String())
					return
				}
			}
		}
	}()
}
