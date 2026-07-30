package guardrails

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ErrSessionStopped is the cancel cause used for a graceful, requested stop (as
// opposed to a kill-switch trip). The server layer matches on it so an
// agent-requested shutdown exits cleanly instead of looking like a crash.
var ErrSessionStopped = errors.New("session stopped")

// SystemActuator performs the OS-level containment actions the kill switch can
// escalate to. All methods are best-effort; the Windows implementation lives in
// actuator_windows.go and a no-op fake in actuator_stub.go keeps the core
// buildable and testable on non-Windows.
type SystemActuator interface {
	// Elevated reports whether the process can perform admin-only actions
	// (network isolation, process kill, shutdown).
	Elevated() bool
	// IsolateNetwork blocks all non-loopback traffic and returns a restore func
	// that undoes it. Requires elevation.
	IsolateNetwork() (restore func() error, err error)
	// KillProcesses terminates processes matching the given executable names.
	KillProcesses(names []string) []error
	// LockWorkstation locks the interactive session (no elevation required).
	LockWorkstation() error
	// Shutdown initiates a system shutdown after delay. Requires elevation.
	Shutdown(reason string, delay time.Duration) error
}

// KillActionConfig selects which escalations run on a trip. Actions are applied
// in a fixed order (isolate → kill-procs → lock → shutdown); each is opt-in and
// configured separately from the trigger signals.
type KillActionConfig struct {
	Isolate       bool
	KillProcs     bool
	Lock          bool
	Shutdown      bool
	ProcNames     []string
	ShutdownDelay time.Duration
}

// DefaultKillActionConfig is the safe default: isolate the device and abort the
// session, but never kill unrelated processes or shut down.
func DefaultKillActionConfig() KillActionConfig {
	return KillActionConfig{Isolate: true}
}

// KillExecutor performs the tiered actions when the kill switch trips. It is
// wired as the KillSwitch onTrip callback. Regardless of configured
// escalations, every trip ALWAYS: records + seals the audit chain, raises the
// on-screen security banner, finalizes the recording, and aborts the session.
// Elevation-only escalations degrade gracefully (skipped + audited) when the
// process is not elevated.
type KillExecutor struct {
	cfg      KillActionConfig
	act      SystemActuator
	audit    *AuditLog
	logger   *slog.Logger
	banner   func(text string)
	finalize func()
	abort    func(err error)

	mu      sync.Mutex
	restore func() error
}

// KillExecutorDeps wires a KillExecutor. banner/finalize/abort come from the
// desktop+server layer; any may be nil (no-op) for tests.
type KillExecutorDeps struct {
	Config   KillActionConfig
	Actuator SystemActuator
	Audit    *AuditLog
	Logger   *slog.Logger
	Banner   func(text string)
	Finalize func()
	Abort    func(err error)
}

func NewKillExecutor(d KillExecutorDeps) *KillExecutor {
	logger := d.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &KillExecutor{
		cfg: d.Config, act: d.Actuator, audit: d.Audit, logger: logger,
		banner: d.Banner, finalize: d.Finalize, abort: d.Abort,
	}
}

// OnTrip runs the tiered response. Ordering is deliberate and must not change:
// seal the audit chain and finalize the recording BEFORE any shutdown, or the
// forensic trail is lost. See the plan's "ordering hazards".
func (e *KillExecutor) OnTrip(reason string) {
	e.audit.append("killswitch.trip", map[string]any{"reason": reason}) // ALWAYS, first
	e.logger.Error("killswitch.trip", "reason", reason)
	if e.banner != nil { // ALWAYS: human-visible, captured by the recording
		e.banner("SECURITY EVENT — session terminating: " + reason)
	}
	if e.audit != nil { // ALWAYS: seal the chain before anything destructive
		_ = e.audit.Flush()
	}

	elevated := e.act != nil && e.act.Elevated()

	if e.cfg.Isolate {
		switch {
		case e.act == nil:
		case !elevated:
			e.audit.append("killaction.skip", map[string]any{"action": "isolate", "why": "not elevated"})
		default:
			if restore, err := e.act.IsolateNetwork(); err != nil {
				e.audit.append("killaction.error", map[string]any{"action": "isolate", "err": err.Error()})
			} else {
				e.mu.Lock()
				e.restore = restore
				e.mu.Unlock()
				e.audit.append("killaction.done", map[string]any{"action": "isolate"})
			}
		}
	}

	if e.cfg.KillProcs {
		if elevated && e.act != nil {
			errs := e.act.KillProcesses(e.cfg.ProcNames)
			e.audit.append("killaction.done", map[string]any{"action": "kill-procs", "targets": e.cfg.ProcNames, "errors": len(errs)})
		} else {
			e.audit.append("killaction.skip", map[string]any{"action": "kill-procs", "why": "not elevated"})
		}
	}

	if e.cfg.Lock && e.act != nil { // no elevation required
		if err := e.act.LockWorkstation(); err != nil {
			e.audit.append("killaction.error", map[string]any{"action": "lock", "err": err.Error()})
		} else {
			e.audit.append("killaction.done", map[string]any{"action": "lock"})
		}
	}

	if e.finalize != nil { // ALWAYS: flush the recording BEFORE any shutdown
		e.finalize()
	}

	if e.cfg.Shutdown {
		if elevated && e.act != nil {
			_ = e.audit.Flush()
			if err := e.act.Shutdown(reason, e.cfg.ShutdownDelay); err != nil {
				e.audit.append("killaction.error", map[string]any{"action": "shutdown", "err": err.Error()})
			}
		} else {
			e.audit.append("killaction.skip", map[string]any{"action": "shutdown", "why": "not elevated"})
		}
	}

	if e.audit != nil {
		_ = e.audit.Flush()
	}
	if e.abort != nil { // ALWAYS, last
		e.abort(fmt.Errorf("kill switch: %s", reason))
	}
}

// StopGracefully ends the session with no containment: it audits the stop, seals
// the chain, finalizes the recording, and aborts. It backs the agent-facing Kill
// tool when the kill switch is not armed, so an agent asking to stop cleanly
// cannot escalate to network isolation, process termination, or shutdown. The
// authoritative triggers still route through OnTrip.
func (e *KillExecutor) StopGracefully(reason string) {
	e.audit.append("session.stop", map[string]any{"reason": reason})
	e.logger.Info("session.stop", "reason", reason)
	if e.audit != nil {
		_ = e.audit.Flush()
	}
	if e.finalize != nil { // flush the recording before the transport closes
		e.finalize()
	}
	if e.audit != nil {
		_ = e.audit.Flush()
	}
	if e.abort != nil {
		e.abort(fmt.Errorf("%w: %s", ErrSessionStopped, reason))
	}
}

// Restore undoes network isolation if it was applied. Called on process exit.
func (e *KillExecutor) Restore() error {
	e.mu.Lock()
	r := e.restore
	e.restore = nil
	e.mu.Unlock()
	if r == nil {
		return nil
	}
	return r()
}

// append is a nil-safe audit helper.
func (a *AuditLog) append(event string, payload any) {
	if a == nil {
		return
	}
	_, _ = a.Append(event, payload)
}
