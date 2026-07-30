//go:build windows && (amd64 || arm64)

package desktop

import "testing"

// TestScrollDirectionIsIndependentOfClickCount is the regression guard.
//
// The wheel sign used to be read off wheelDelta*int32(wheelClicks). That product
// overflows int32 at 17_895_698 clicks, flipping negative, so an "up" scroll
// silently became a "down" scroll. Direction and magnitude are now decided
// separately, which is why this test can assert direction without a count at all.
func TestScrollDirectionIsIndependentOfClickCount(t *testing.T) {
	for _, tc := range []struct {
		direction        string
		down, horizontal bool
	}{
		{"up", false, false},
		{"down", true, false},
		{"left", true, true},
		{"right", false, true},
	} {
		down, horizontal := scrollDirection(tc.direction)
		if down != tc.down || horizontal != tc.horizontal {
			t.Errorf("scrollDirection(%q) = (down=%v, horizontal=%v), want (down=%v, horizontal=%v)",
				tc.direction, down, horizontal, tc.down, tc.horizontal)
		}
	}
}

// TestScrollDirectionUnknownScrollsDown pins the fallback, which matches the
// Python implementation this engine was ported from.
func TestScrollDirectionUnknownScrollsDown(t *testing.T) {
	for _, d := range []string{"", "sideways", "UP", "Down"} {
		if down, horizontal := scrollDirection(d); !down || horizontal {
			t.Errorf("scrollDirection(%q) = (down=%v, horizontal=%v), want (true, false)", d, down, horizontal)
		}
	}
}

// TestBoundWheelClicks covers the clamp that keeps an agent-supplied notch count
// from holding the engine's one STA thread. The loop sleeps 10ms per notch, so
// an unbounded count is a session-length stall, not just a slow call.
func TestBoundWheelClicks(t *testing.T) {
	for _, tc := range []struct{ in, want int }{
		{0, 1},
		{-1, 1},
		{-1 << 40, 1},
		{1, 1},
		{500, 500},
		{maxWheelClicks, maxWheelClicks},
		{maxWheelClicks + 1, maxWheelClicks},
		{20_000_000, maxWheelClicks},
		{1 << 40, maxWheelClicks},
	} {
		if got := boundWheelClicks(tc.in); got != tc.want {
			t.Errorf("boundWheelClicks(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestBoundWheelClicksKeepsTheCallShort ties the bound to why it exists: at 10ms
// per notch the worst case must stay in the seconds, not the hours.
func TestBoundWheelClicksKeepsTheCallShort(t *testing.T) {
	const perClickMillis = 10
	if worst := boundWheelClicks(1 << 40) * perClickMillis; worst > 60_000 {
		t.Errorf("worst-case Scroll holds the STA thread for %dms; keep it under a minute", worst)
	}
}
