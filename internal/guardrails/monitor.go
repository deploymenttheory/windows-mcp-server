package guardrails

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MonitorConfig configures continuous verification.
type MonitorConfig struct {
	// Interval re-runs the enforce set (0 disables posture-drift checks).
	Interval time.Duration
	// ControlDir is watched for a "kill" sentinel file (empty disables).
	ControlDir string
	// Evaluate re-runs the guardrail set and returns the current decision.
	Evaluate func(ctx context.Context) Decision
	Kill     *KillSwitch
	Logger   *slog.Logger
}

// StartMonitor launches the continuous-verification loop: it re-evaluates
// posture on Interval (tripping the kill switch if admission flips) and watches
// for a local sentinel file. It returns immediately; the goroutine stops when
// ctx is cancelled.
func StartMonitor(ctx context.Context, cfg MonitorConfig) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Interval <= 0 && cfg.ControlDir == "" {
		return // nothing to do
	}
	tick := cfg.Interval
	if tick <= 0 || (cfg.ControlDir != "" && tick > 5*time.Second) {
		// Poll at least every 5s when watching a sentinel.
		tick = 5 * time.Second
	}

	go func() {
		t := time.NewTicker(tick)
		defer t.Stop()
		var lastEval time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}

			if cfg.ControlDir != "" {
				if _, err := os.Stat(filepath.Join(cfg.ControlDir, "kill")); err == nil {
					cfg.Kill.Trip("local sentinel: kill file present")
					return
				}
			}

			if cfg.Interval > 0 && cfg.Evaluate != nil && time.Since(lastEval) >= cfg.Interval {
				lastEval = time.Now()
				d := cfg.Evaluate(ctx)
				LogDecision(cfg.Logger, "periodic", d)
				if !d.Admit {
					cfg.Kill.Trip("posture drift: " + strings.Join(d.Reasons, "; "))
					return
				}
			}
		}
	}()
}
