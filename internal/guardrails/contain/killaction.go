package contain

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
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
	//
	// observed reports what the OS said the state was after the change, read back
	// through the same interface that made it. A nil error means the calls
	// succeeded; it does not mean anything changed, and the difference is not
	// something an audit trail should have to assume. Recorded with the trip.
	IsolateNetwork() (restore func() error, observed []string, err error)
	// KillProcesses terminates processes matching the given executable names.
	KillProcesses(names []string) []error
	// LockWorkstation locks the interactive session (no elevation required).
	LockWorkstation() error
	// Shutdown initiates a system shutdown after delay. Requires elevation.
	Shutdown(reason string, delay time.Duration) error
}

// ErrKillSwitchTripped is the cause an aborted session carries.
var ErrKillSwitchTripped = errors.New("kill switch")

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
	audit    *audit.AuditLog
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
	Audit    *audit.AuditLog
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
	// The ALWAYS steps -- banner, seal, finalize, abort -- are the forensic trail,
	// and a panic anywhere below would skip whatever had not run yet. This runs on
	// the monitor or watchdog goroutine, so without a recover a panic here takes
	// the process down without finalizing the recording or aborting the session:
	// exactly the evidence the ordering exists to protect. internal/desktop has
	// safeCall for the same reason; the kill path had no equivalent.
	defer func() {
		if r := recover(); r != nil {
			e.logger.Error("panic during the kill ladder; the session is being aborted anyway",
				"panic", r, "reason", reason)
			if e.finalize != nil {
				e.finalize()
			}
			if e.audit != nil {
				_ = e.audit.Flush()
			}
			if e.abort != nil {
				e.abort(fmt.Errorf("%w: %s (panic during containment)", ErrKillSwitchTripped, reason))
			}
		}
	}()

	auditAppend(e.audit, "killswitch.tripped", map[string]any{"reason": reason}) // ALWAYS, first
	e.logger.Error("killswitch.tripped", "reason", reason)
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
			auditAppend(e.audit, "killaction.skipped", map[string]any{"action": "isolate", "why": "not elevated"})
		default:
			restore, observed, err := e.act.IsolateNetwork()
			switch {
			case err != nil:
				auditAppend(e.audit, "killaction.failed", map[string]any{
					"action": "isolate", "err": err.Error(), "observed": observed,
				})
			default:
				e.mu.Lock()
				e.restore = restore
				e.mu.Unlock()
				// observed is what the OS reported after the change. Recording it
				// means "isolate ran" and "isolate took effect" are separate claims
				// in the chain, which is the distinction a containment record has to
				// support: killaction.done alone could not tell them apart.
				auditAppend(e.audit, "killaction.done", map[string]any{
					"action": "isolate", "observed": observed,
				})
			}
		}
	}

	if e.cfg.KillProcs {
		if elevated && e.act != nil {
			errs := e.act.KillProcesses(e.cfg.ProcNames)
			auditAppend(e.audit,
				"killaction.done",
				map[string]any{"action": "kill-procs", "targets": e.cfg.ProcNames, "errors": len(errs)},
			)
		} else {
			auditAppend(e.audit, "killaction.skipped", map[string]any{"action": "kill-procs", "why": "not elevated"})
		}
	}

	if e.cfg.Lock && e.act != nil { // no elevation required
		if err := e.act.LockWorkstation(); err != nil {
			auditAppend(e.audit, "killaction.failed", map[string]any{"action": "lock", "err": err.Error()})
		} else {
			auditAppend(e.audit, "killaction.done", map[string]any{"action": "lock"})
		}
	}

	if e.finalize != nil { // ALWAYS: flush the recording BEFORE any shutdown
		e.finalize()
	}

	if e.cfg.Shutdown {
		if elevated && e.act != nil {
			// Nil-guarded like every other audit site here. KillExecutorDeps
			// documents that any dependency may be nil, and this one call was bare:
			// AuditLog.Flush takes its mutex before checking anything, so a nil log
			// panicked mid-ladder with shutdown armed.
			if e.audit != nil {
				_ = e.audit.Flush()
			}
			if err := e.act.Shutdown(reason, e.cfg.ShutdownDelay); err != nil {
				auditAppend(e.audit, "killaction.failed", map[string]any{"action": "shutdown", "err": err.Error()})
			}
		} else {
			auditAppend(e.audit, "killaction.skipped", map[string]any{"action": "shutdown", "why": "not elevated"})
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
	auditAppend(e.audit, "session.stopped", map[string]any{"reason": reason})
	e.logger.Info("session.stopped", "reason", reason)
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

// auditAppend is a nil-safe audit helper.
//
// It is a function rather than a method because AuditLog belongs to another
// package now. That it could ever be a method was an artefact of everything
// living in one package.
func auditAppend(a *audit.AuditLog, event string, payload any) {
	if a == nil {
		return
	}
	_, _ = a.Append(event, payload)
}
