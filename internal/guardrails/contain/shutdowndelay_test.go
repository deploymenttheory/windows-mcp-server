//go:build windows && (amd64 || arm64)

package contain

import (
	"testing"
	"time"
)

// TestShutdownSecondsNeverWraps is the regression guard on the kill ladder's
// last containment step.
//
// InitiateSystemShutdownEx takes dwTimeout as a uint32 of seconds, and the delay
// comes from --kill-action-shutdown-delay — operator input. A bare
// uint32(delay / time.Second) turns a negative duration into roughly 136 years,
// so a mistyped flag would leave the shutdown scheduled past any plausible
// horizon: the switch reports that it fired, and the machine never goes down.
func TestShutdownSecondsNeverWraps(t *testing.T) {
	for _, tc := range []struct {
		name  string
		delay time.Duration
		want  uint32
	}{
		{"zero is immediate", 0, 0},
		{"ordinary delay", 90 * time.Second, 90},
		{"sub-second truncates down", 900 * time.Millisecond, 0},
		{"negative clamps to immediate", -5 * time.Minute, 0},
		{"most negative clamps to immediate", time.Duration(-1 << 62), 0},
		{"at the ceiling", maxShutdownDelay, uint32(maxShutdownDelay / time.Second)},
		{"past the ceiling clamps", maxShutdownDelay * 2, uint32(maxShutdownDelay / time.Second)},
		{"max duration clamps", time.Duration(1<<62 - 1), uint32(maxShutdownDelay / time.Second)},
	} {
		if got := shutdownSeconds(tc.delay); got != tc.want {
			t.Errorf("%s: shutdownSeconds(%v) = %d, want %d", tc.name, tc.delay, got, tc.want)
		}
	}
}

// TestShutdownSecondsClampsTowardContainment states the direction of the two
// clamps as a property: whatever the operator typed, the resulting delay is
// never longer than what they asked for. Erring short shuts the machine down
// sooner than intended; erring long is what silently disables the kill.
func TestShutdownSecondsClampsTowardContainment(t *testing.T) {
	for _, d := range []time.Duration{
		-time.Hour, 0, time.Second, time.Hour, maxShutdownDelay, maxShutdownDelay + time.Hour,
		time.Duration(1<<62 - 1),
	} {
		got := time.Duration(shutdownSeconds(d)) * time.Second
		if d > 0 && got > d {
			t.Errorf("shutdownSeconds(%v) = %v, which is longer than requested", d, got)
		}
		if got > maxShutdownDelay {
			t.Errorf("shutdownSeconds(%v) = %v, past the Windows ceiling %v", d, got, maxShutdownDelay)
		}
	}
}
