//go:build windows && (amd64 || arm64)

package desktop

import (
	"errors"
	"math"
	"strings"
	"testing"
)

// TestScreenCoordRejectsOutOfRange is the regression guard for unvalidated agent
// input reaching a syscall. Coordinates arrive from tool arguments and were cast
// with a bare int32(v), which wraps on a 64-bit build: int32(1<<32 + 100) is 100,
// so an absurd coordinate would quietly act on a real point on screen instead of
// failing.
func TestScreenCoordRejectsOutOfRange(t *testing.T) {
	// The exact value that motivated the fix. Note it must be a variable: Go
	// rejects int32(<constant too large>) at compile time, but silently wraps the
	// same conversion on a runtime value — which is why an agent-supplied
	// coordinate was dangerous and a literal never would be.
	wrapsTo100 := int(math.MaxUint32) + 101
	if int32(wrapsTo100) != 100 { //nolint:gosec // demonstrating the wrap this guard prevents
		t.Fatalf("premise wrong: int32(%d) = %d, expected the wrap to 100", wrapsTo100, int32(wrapsTo100))
	}
	switch _, err := screenCoord(wrapsTo100, "x coordinate"); {
	case err == nil:
		t.Error("a coordinate that wraps to a valid point must be rejected, not silently wrapped")
	case !errors.Is(err, ErrCoordinateOutOfRange):
		t.Errorf("want ErrCoordinateOutOfRange, got %v", err)
	}

	for _, v := range []int{math.MaxInt32 + 1, math.MinInt32 - 1, math.MaxInt64, math.MinInt64} {
		if _, err := screenCoord(v, "x coordinate"); err == nil {
			t.Errorf("screenCoord(%d) should be rejected", v)
		}
	}
}

// TestScreenCoordAcceptsValidIncludingNegative pins that negative coordinates
// stay legal: a multi-monitor virtual desktop legitimately has a negative origin,
// so clamping to non-negative would break secondary displays.
func TestScreenCoordAcceptsValidIncludingNegative(t *testing.T) {
	for _, v := range []int{0, 1, -1, 1920, -3840, math.MaxInt32, math.MinInt32} {
		got, err := screenCoord(v, "x coordinate")
		if err != nil {
			t.Errorf("screenCoord(%d) should be accepted: %v", v, err)
			continue
		}
		if int(got) != v {
			t.Errorf("screenCoord(%d) = %d, value must be preserved", v, got)
		}
	}
}

// TestScreenCoordErrorNamesTheAxis keeps the message actionable for the model.
func TestScreenCoordErrorNamesTheAxis(t *testing.T) {
	_, err := screenCoord(math.MaxInt64, "y coordinate")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "y coordinate") {
		t.Errorf("error should name the axis, got %q", err)
	}
}

// TestScreenPointValidatesBothAxes ensures neither axis is skipped.
func TestScreenPointValidatesBothAxes(t *testing.T) {
	if _, _, err := screenPoint(math.MaxInt64, 10); err == nil {
		t.Error("bad x must be rejected")
	}
	if _, _, err := screenPoint(10, math.MaxInt64); err == nil {
		t.Error("bad y must be rejected")
	}
	x, y, err := screenPoint(-1920, 1080)
	if err != nil {
		t.Fatalf("valid pair rejected: %v", err)
	}
	if x != -1920 || y != 1080 {
		t.Errorf("screenPoint returned (%d,%d), want (-1920,1080)", x, y)
	}
}

// TestSetCursorRejectsBeforeSyscall proves the guard runs before any Win32 call:
// an out-of-range point must fail without moving the real cursor.
func TestSetCursorRejectsBeforeSyscall(t *testing.T) {
	err := setCursor(math.MaxInt64, math.MaxInt64)
	if err == nil {
		t.Fatal("out-of-range point must be refused")
	}
	if strings.Contains(err.Error(), "SetCursorPos") {
		t.Errorf("should fail validation before reaching SetCursorPos, got %q", err)
	}
}
