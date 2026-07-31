// Package contain is the response: the out-of-band kill switch and the tiered
// containment ladder it runs.
//
// It is deliberately not reachable from the agent surface. The authoritative
// triggers call Trip directly, so a misbehaving model cannot disable it, and the
// agent-facing Kill tool routes to a graceful stop unless the policy configures
// containment.
//
// The ladder's ordering is load-bearing and must not change: audit, banner and
// seal happen before anything destructive, and the recording is finalized before
// shutdown, or the forensic trail is lost with the session.
package contain

import (
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
