package guardrails

import (
	"encoding/json"
	"sync/atomic"
	"testing"
)

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

func TestDecisionJSONRoundTrips(t *testing.T) {
	d := Decision{
		Device:  DeviceIdentity{Hostname: "H"},
		Mode:    "enforce",
		Admit:   false,
		Reasons: []string{"x"},
		Results: []Result{{ID: "run-context", Status: Pass}},
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var back Decision
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Admit || back.Mode != "enforce" || len(back.Results) != 1 {
		t.Errorf("round-trip mismatch: %+v", back)
	}
}
