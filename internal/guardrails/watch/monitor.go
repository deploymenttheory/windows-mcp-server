package watch

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/signals"
)

// MonitorConfig configures continuous verification.
type MonitorConfig struct {
	// Interval re-runs the enforce set (0 disables posture-drift checks).
	Interval time.Duration
	// ControlDir is watched for a "kill" sentinel file (empty disables).
	ControlDir string
	// SentinelToken must appear in the kill file for the sentinel to be obeyed.
	//
	// The sentinel used to be authenticated by its own existence, which made it an
	// agent-reachable route into the containment ladder: one FileSystem write, or
	// any PowerShell redirect, and a policy with isolate or shutdown armed did
	// exactly that — the escalation the design says an agent must never be able to
	// ask for. A token the server mints at startup and logs once is something the
	// operator has and the agent does not.
	//
	// Empty means unauthenticated, retained only so an operator who has not moved
	// to a token is not silently left with a trigger that never fires; RunStdio
	// always sets it.
	SentinelToken string
	// Evaluate re-runs the guardrail set and returns the current decision.
	Evaluate func(ctx context.Context) signals.Decision
	// Verify holds the always-on in-flight checks (heartbeat, rug-pull recheck,
	// status refresh). They run on every tick regardless of Interval and are not
	// agent-disableable. A non-nil error fires that check's own Trip.
	Verify []VerifyFunc
	// TripSentinel fires when the local sentinel file appears; TripPostureDrift
	// fires when a periodic re-evaluation stops admitting. Each is supplied by the
	// caller already gated on its operator flag, so a trigger the operator left
	// disabled is report-only rather than absent — detection and audit are never
	// conditional on containment.
	TripSentinel     func(reason string)
	TripPostureDrift func(reason string)
	// Stopped reports whether the server is genuinely being torn down. The loop
	// exits only when it returns true, so a report-only trip does not silently end
	// all further monitoring.
	Stopped func() bool
	Logger  *slog.Logger
}

// VerifyFunc is one always-on in-flight check. Name is used in the trip reason
// and Trip is that check's caller-gated trip function.
type VerifyFunc struct {
	Name string
	Run  func(ctx context.Context) error
	Trip func(reason string)
}

// StartMonitor launches the continuous-verification loop: it re-evaluates
// posture on Interval (tripping the kill switch if admission flips) and watches
// for a local sentinel file. It returns immediately; the goroutine stops when
// ctx is cancelled or Stopped reports the server is going down.
func StartMonitor(ctx context.Context, cfg MonitorConfig) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Interval <= 0 && cfg.ControlDir == "" && len(cfg.Verify) == 0 {
		return // nothing to do
	}
	tick := cfg.Interval
	if tick <= 0 || ((cfg.ControlDir != "" || len(cfg.Verify) > 0) && tick > 5*time.Second) {
		// Poll at least every 5s when watching a sentinel or running verifiers.
		tick = 5 * time.Second
	}

	go func() {
		t := time.NewTicker(tick)
		defer t.Stop()
		var lastEval time.Time
		var sentinelSeen bool
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}

			if cfg.ControlDir != "" && !sentinelSeen {
				if authentic, present := cfg.readSentinel(); present {
					// Report once either way: the file stays present, and a
					// report-only trigger would otherwise re-audit it on every tick.
					sentinelSeen = true
					if !authentic {
						// Detected and recorded, but not obeyed. A sentinel the agent
						// could have written is not an operator instruction.
						if cfg.Logger != nil {
							cfg.Logger.Warn("ignoring a kill sentinel that does not carry the "+
								"session token; the token is logged once at startup",
								"control_dir", cfg.ControlDir)
						}
						continue
					}
					fire(cfg.TripSentinel, "local sentinel: kill file present")
					if cfg.stopped() {
						return
					}
				}
			}

			// Always-on in-flight verifiers (heartbeat, rug-pull, status refresh).
			for _, v := range cfg.Verify {
				if v.Run == nil {
					continue
				}
				if err := v.Run(ctx); err != nil {
					fire(v.Trip, v.Name+": "+err.Error())
					if cfg.stopped() {
						return
					}
				}
			}

			if cfg.Interval > 0 && cfg.Evaluate != nil && time.Since(lastEval) >= cfg.Interval {
				lastEval = time.Now()
				d := cfg.Evaluate(ctx)
				signals.LogDecision(cfg.Logger, "periodic", d)
				if !d.Admit {
					fire(cfg.TripPostureDrift, "posture drift: "+strings.Join(d.Reasons, "; "))
					if cfg.stopped() {
						return
					}
				}
			}
		}
	}()
}

// fire invokes a caller-supplied trip function, tolerating nil (no trigger wired).
func fire(trip func(string), reason string) {
	if trip != nil {
		trip(reason)
	}
}

// stopped reports whether the monitor loop should exit.
func (cfg MonitorConfig) stopped() bool {
	return cfg.Stopped != nil && cfg.Stopped()
}

// readSentinel reports whether the kill file is present and, if so, whether it
// carries the session token.
//
// Presence and authenticity are returned separately on purpose: a sentinel the
// agent could have written is still worth recording, so the operator sees that
// something tried, even though it is not obeyed.
//
// The comparison is constant-time. The token is not a high-value secret — it
// authorises a shutdown, not access to data — but comparing it byte-by-byte would
// leak it to anything that can write the file and watch the log, which is exactly
// the position the agent is in.
func (c MonitorConfig) readSentinel() (authentic, present bool) {
	raw, err := os.ReadFile(filepath.Join(c.ControlDir, "kill")) //nolint:gosec // an operator-configured control path
	if err != nil {
		return false, false
	}
	if c.SentinelToken == "" {
		return true, true // unauthenticated mode: presence is the signal
	}
	got := strings.TrimSpace(string(raw))
	return subtle.ConstantTimeCompare([]byte(got), []byte(c.SentinelToken)) == 1, true
}
