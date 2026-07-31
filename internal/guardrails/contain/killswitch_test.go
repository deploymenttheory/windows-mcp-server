package contain

import (
	"sync/atomic"
	"testing"
)

// TestKillSwitchFiresOnce pins idempotency. A trip runs the containment ladder,
// and a ladder that ran twice would isolate an already-isolated device, seal an
// already-sealed chain, and report two incidents for one event.
func TestKillSwitchFiresOnce(t *testing.T) {
	var n int32
	k := NewKillSwitch(func(string) { atomic.AddInt32(&n, 1) })
	k.Trip("a")
	k.Trip("b")
	if got := atomic.LoadInt32(&n); got != 1 {
		t.Errorf("onTrip called %d times, want 1", got)
	}
	if tripped, reason := k.Tripped(); !tripped || reason != "a" {
		t.Errorf("Tripped() = %v, %q; want true, \"a\"", tripped, reason)
	}
}
