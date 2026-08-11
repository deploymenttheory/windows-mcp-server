//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/deploymenttheory/agentweave-harness/guardrails/audit"
	"github.com/deploymenttheory/agentweave-harness/guardrails/policy"
)

// eventLogSource is the Application-log source name the anchor writes under. If it
// has not been registered (which needs elevation), Windows still records the event
// with the head text intact, wrapped in a "description not found" notice — the
// forensic value is the head, which is present either way.
const eventLogSource = "windows-mcp-server"

// anchorWriter publishes an audit chain head somewhere the running session cannot
// reach back into.
type anchorWriter interface {
	publish(seq uint64, head string)
}

// startAnchor launches the anchoring loop for a configured destination, returning
// a stop function. A disabled (empty destination) policy returns a no-op, so the
// caller does not special-case it. Anchoring is defence-in-depth: if the off-box
// writer cannot be opened it degrades to chain-only anchoring with a warning, and
// never fails startup.
func startAnchor(ctx context.Context, p policy.AnchorPolicy, auditLog *audit.AuditLog, logger *slog.Logger) func() {
	if p.Destination == "" {
		return func() {}
	}

	var w anchorWriter
	switch p.Destination {
	case policy.AnchorEventLog:
		w = newEventLogWriter(logger)
	default:
		// Validation rejects unknown destinations, so this is unreachable from a
		// loaded policy; guard anyway rather than anchor to nothing silently.
		logger.Warn("audit anchor: unknown destination, anchoring to the chain only",
			"destination", p.Destination)
	}

	loopCtx, cancel := context.WithCancel(ctx)
	go runAnchor(loopCtx, p.Cadence.Std(), auditLog, w)
	return cancel
}

// runAnchor anchors the chain head on every tick until the context is cancelled.
func runAnchor(ctx context.Context, cadence time.Duration, auditLog *audit.AuditLog, w anchorWriter) {
	ticker := time.NewTicker(cadence)
	defer ticker.Stop()
	last := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			last = anchorOnce(auditLog, last, w)
		}
	}
}

// anchorOnce writes one audit.anchored entry naming the current head and publishes
// it off-box, but only when the head has advanced since lastHead. Without that
// guard an idle server would grow its own chain by one anchor entry per tick
// forever — each anchor advances the head, so the next tick would always see a
// "new" head. It returns the head to remember for the next tick (the post-append
// head, so a quiet interval compares equal and is skipped).
func anchorOnce(auditLog *audit.AuditLog, lastHead string, w anchorWriter) string {
	seq, head := auditLog.Head()
	if head == "" || head == lastHead {
		return lastHead
	}
	_, _ = auditLog.Append("audit.anchored", map[string]any{
		"anchored_seq":  seq,
		"anchored_head": head,
	})
	if w != nil {
		w.publish(seq, head)
	}
	_, newHead := auditLog.Head()
	return newHead
}

// eventLogWriter publishes heads to the Windows Application event log.
type eventLogWriter struct {
	log    *eventlog.Log
	logger *slog.Logger
}

func newEventLogWriter(logger *slog.Logger) anchorWriter {
	l, err := eventlog.Open(eventLogSource)
	if err != nil {
		logger.Warn("audit anchor: event log unavailable, anchoring to the chain only", "error", err)
		return nil
	}
	return &eventLogWriter{log: l, logger: logger}
}

func (w *eventLogWriter) publish(seq uint64, head string) {
	if err := w.log.Info(1, fmt.Sprintf("windows-mcp-server audit anchor: seq=%d head=%s", seq, head)); err != nil {
		w.logger.Warn("audit anchor: could not write to event log", "error", err)
	}
}
