//go:build windows && (amd64 || arm64)

package winmcp

// harnessrungs builds the actuation table the servant executes on the harness's
// command. Each rung maps onto exactly the primitive the in-process kill
// executor already uses, so there is one actuation path on this host regardless
// of where the decision to trip was made. The harness owns the ladder's
// ordering (transparency before containment); this table owns only how a single
// rung is carried out, and reports back honestly — a rung the process cannot
// perform is reported skipped with a reason, never faked.

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/deploymenttheory/agentweave-harness/guardrails/contain"
	"github.com/deploymenttheory/agentweave-harness/guardrails/egress"
	"github.com/deploymenttheory/agentweave-harness/wire"
)

// rungPrimitives is what RunStdio supplies to build the actuation table. Every
// field is one already-wired capability of the running server.
type rungPrimitives struct {
	Actuator     contain.SystemActuator
	Banner       func(text string)
	Seal         func() error       // flush + seal the audit chain
	Finalize     func()             // finalize the recording (idempotent)
	CleanupCreds func()             // revoke installed session credentials
	SetRestore   func(func() error) // hand the network-isolation undo to the exit path
	// Egress is the OS firewall enforcer the egress rungs actuate through. The
	// harness holds the composed egress policy and drives its OS enforcement
	// on the host over the channel; this is a fresh WindowsEnforcer because
	// the policy path's enforcer state lives on disk, not in a shared object.
	Egress egress.Enforcer
	// EgressRestore holds the undo returned by an egress_apply, so the
	// egress_restore rung and the exit defer can both run it, once.
	EgressRestore *egressRestoreHolder
	Logger        *slog.Logger
}

// egressRestoreHolder carries the undo an egress_apply installed, so the
// explicit egress_restore rung and the exit defer both reach it and neither
// double-runs it.
type egressRestoreHolder struct {
	mu sync.Mutex
	fn func() error
}

func (h *egressRestoreHolder) set(fn func() error) {
	h.mu.Lock()
	h.fn = fn
	h.mu.Unlock()
}

// run executes and clears the stashed restore. A second call is a no-op, so
// the exit defer and an explicit egress_restore cannot both fire it.
func (h *egressRestoreHolder) run() error {
	h.mu.Lock()
	fn := h.fn
	h.fn = nil
	h.mu.Unlock()
	if fn == nil {
		return nil
	}
	return fn()
}

// buildRungs assembles the rung table. The set is closed and named here; a rung
// absent from it is refused by the servant as unknown.
func buildRungs(p rungPrimitives) map[string]rungFunc {
	elevated := p.Actuator != nil && p.Actuator.Elevated()

	return map[string]rungFunc{
		wire.RungBanner: func(params json.RawMessage) wire.ActuateResult {
			text := "SECURITY EVENT — session terminating"
			var pl struct {
				Text string `json:"text"`
			}
			if json.Unmarshal(params, &pl) == nil && pl.Text != "" {
				text = pl.Text
			}
			if p.Banner != nil {
				p.Banner(text)
			}
			return wire.ActuateResult{Rung: wire.RungBanner, OK: true}
		},

		wire.RungSeal: func(json.RawMessage) wire.ActuateResult {
			if p.Seal != nil {
				if err := p.Seal(); err != nil {
					return wire.ActuateResult{Rung: wire.RungSeal, OK: false, SkippedReason: err.Error()}
				}
			}
			return wire.ActuateResult{Rung: wire.RungSeal, OK: true}
		},

		wire.RungFinalizeRecording: func(json.RawMessage) wire.ActuateResult {
			if p.Finalize != nil {
				p.Finalize()
			}
			return wire.ActuateResult{Rung: wire.RungFinalizeRecording, OK: true}
		},

		wire.RungCredentialCleanup: func(json.RawMessage) wire.ActuateResult {
			if p.CleanupCreds != nil {
				p.CleanupCreds()
			}
			return wire.ActuateResult{Rung: wire.RungCredentialCleanup, OK: true}
		},

		wire.RungIsolate: func(json.RawMessage) wire.ActuateResult {
			if p.Actuator == nil || !elevated {
				return wire.ActuateResult{Rung: wire.RungIsolate, OK: false, SkippedReason: "not elevated"}
			}
			restore, observed, err := p.Actuator.IsolateNetwork()
			if err != nil {
				return wire.ActuateResult{
					Rung: wire.RungIsolate, OK: false, Observed: observed, SkippedReason: err.Error(),
				}
			}
			if p.SetRestore != nil {
				p.SetRestore(restore)
			}
			return wire.ActuateResult{Rung: wire.RungIsolate, OK: true, Observed: observed}
		},

		wire.RungKillProcs: func(params json.RawMessage) wire.ActuateResult {
			if p.Actuator == nil || !elevated {
				return wire.ActuateResult{Rung: wire.RungKillProcs, OK: false, SkippedReason: "not elevated"}
			}
			var pl struct {
				Names []string `json:"names"`
			}
			_ = json.Unmarshal(params, &pl)
			errs := p.Actuator.KillProcesses(pl.Names)
			return wire.ActuateResult{Rung: wire.RungKillProcs, OK: len(errs) == 0, Observed: pl.Names}
		},

		wire.RungLock: func(json.RawMessage) wire.ActuateResult {
			if p.Actuator == nil {
				return wire.ActuateResult{Rung: wire.RungLock, OK: false, SkippedReason: "no actuator"}
			}
			if err := p.Actuator.LockWorkstation(); err != nil {
				return wire.ActuateResult{Rung: wire.RungLock, OK: false, SkippedReason: err.Error()}
			}
			return wire.ActuateResult{Rung: wire.RungLock, OK: true}
		},

		wire.RungShutdown: func(params json.RawMessage) wire.ActuateResult {
			if p.Actuator == nil || !elevated {
				return wire.ActuateResult{Rung: wire.RungShutdown, OK: false, SkippedReason: "not elevated"}
			}
			var pl struct {
				Reason  string `json:"reason"`
				DelayMS int    `json:"delay_ms"`
			}
			_ = json.Unmarshal(params, &pl)
			if err := p.Actuator.Shutdown(pl.Reason, time.Duration(pl.DelayMS)*time.Millisecond); err != nil {
				return wire.ActuateResult{Rung: wire.RungShutdown, OK: false, SkippedReason: err.Error()}
			}
			return wire.ActuateResult{Rung: wire.RungShutdown, OK: true}
		},

		// Egress rungs actuate the composed egress policy's OS enforcement on
		// the host: the harness holds the policy and proxy, this host owns the
		// firewall and WinINET. The apply rung stashes its own undo so the
		// restore rung — and the exit defer — can reach it exactly once.
		wire.RungEgressApply: func(params json.RawMessage) wire.ActuateResult {
			if p.Egress == nil || p.EgressRestore == nil {
				return wire.ActuateResult{Rung: wire.RungEgressApply, OK: false, SkippedReason: "no egress enforcer"}
			}
			var pl wire.EgressApplyParams
			if err := json.Unmarshal(params, &pl); err != nil {
				return wire.ActuateResult{Rung: wire.RungEgressApply, OK: false, SkippedReason: err.Error()}
			}
			// The firewall tiers need elevation, mirroring the local path's
			// refusal: serving a weaker posture than the harness policy
			// describes is exactly what the handshake gate already refused, so
			// this can only skip if elevation was lost after the handshake.
			if (len(pl.Applications) > 0 || pl.BlockAllOutbound) && !p.Egress.Elevated() {
				return wire.ActuateResult{Rung: wire.RungEgressApply, OK: false, SkippedReason: "not elevated"}
			}
			restore, err := p.Egress.Apply(egress.EnforceSpec{
				ProxyAddr:       fmt.Sprintf("127.0.0.1:%d", pl.ProxyPort),
				Applications:    pl.Applications,
				GlobalBlock:     pl.BlockAllOutbound,
				AllowPorts:      pl.AllowPorts,
				SetSystemProxy:  pl.SetSystemProxy,
				ProxyExecutable: pl.ProxyExecutable,
			})
			if err != nil {
				return wire.ActuateResult{Rung: wire.RungEgressApply, OK: false, SkippedReason: err.Error()}
			}
			p.EgressRestore.set(restore)
			return wire.ActuateResult{Rung: wire.RungEgressApply, OK: true}
		},

		wire.RungEgressSuspend: func(json.RawMessage) wire.ActuateResult {
			if p.Egress == nil {
				return wire.ActuateResult{Rung: wire.RungEgressSuspend, OK: false, SkippedReason: "no egress enforcer"}
			}
			if err := p.Egress.Suspend(); err != nil {
				return wire.ActuateResult{Rung: wire.RungEgressSuspend, OK: false, SkippedReason: err.Error()}
			}
			return wire.ActuateResult{Rung: wire.RungEgressSuspend, OK: true}
		},

		wire.RungEgressRestore: func(json.RawMessage) wire.ActuateResult {
			if p.EgressRestore == nil {
				return wire.ActuateResult{Rung: wire.RungEgressRestore, OK: false, SkippedReason: "no egress state"}
			}
			if err := p.EgressRestore.run(); err != nil {
				return wire.ActuateResult{Rung: wire.RungEgressRestore, OK: false, SkippedReason: err.Error()}
			}
			return wire.ActuateResult{Rung: wire.RungEgressRestore, OK: true}
		},
	}
}
