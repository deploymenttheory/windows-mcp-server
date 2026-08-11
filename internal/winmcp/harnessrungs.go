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
	"log/slog"
	"time"

	"github.com/deploymenttheory/agentweave-harness/guardrails/contain"
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
	Logger       *slog.Logger
}

// buildRungs assembles the rung table. The set is closed and named here; a rung
// absent from it is refused by the servant as unknown. Egress rungs are
// deliberately not present until the egress proxy relocates to the harness
// (Phase 6), so a request for one is refused rather than half-served.
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
	}
}
