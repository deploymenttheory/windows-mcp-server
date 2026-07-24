package guardrails

import (
	"log/slog"
	"sync"
)

// KillSwitch is the out-of-band stop control. It is deliberately independent of
// the agent/tool surface: the authoritative triggers (posture-drift monitor,
// circuit breaker, remote revoke, local sentinel) call Trip directly, so a
// misbehaving LLM cannot disable it. Trip is idempotent.
type KillSwitch struct {
	mu      sync.Mutex
	tripped bool
	reason  string
	onTrip  func(reason string)
}

// NewKillSwitch returns a kill switch that invokes onTrip once, on the first
// Trip. onTrip should log the reason, finalize the recording, and cancel the
// server context.
func NewKillSwitch(onTrip func(reason string)) *KillSwitch {
	return &KillSwitch{onTrip: onTrip}
}

// Trip fires the kill switch (once).
func (k *KillSwitch) Trip(reason string) {
	k.mu.Lock()
	if k.tripped {
		k.mu.Unlock()
		return
	}
	k.tripped = true
	k.reason = reason
	cb := k.onTrip
	k.mu.Unlock()
	if cb != nil {
		cb(reason)
	}
}

// Tripped reports whether the switch has fired and why.
func (k *KillSwitch) Tripped() (bool, string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.tripped, k.reason
}

// LogDecision emits a structured audit event for a policy decision.
func LogDecision(logger *slog.Logger, event string, d Decision) {
	if logger == nil {
		logger = slog.Default()
	}
	logger.Info("guardrail."+event,
		"mode", d.Mode,
		"admit", d.Admit,
		"device_host", d.Device.Hostname,
		"device_serial", d.Device.Serial,
		"run_context_system", d.RunContext.IsSystem,
		"session", d.SessionID,
		"results", summarizeResults(d.Results),
		"reasons", d.Reasons,
	)
}

func summarizeResults(rs []Result) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.ID+"="+string(r.Status))
	}
	return out
}
