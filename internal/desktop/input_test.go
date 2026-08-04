//go:build windows && (amd64 || arm64)

package desktop

import (
	"errors"
	"strings"
	"testing"
)

// TestSyntheticInputIsBounded pins the caps that keep one call from occupying the
// engine's single serialized thread indefinitely.
//
// TypeText sends a SendInput pair per rune and ClickMany sleeps between points,
// with no upper bound on either -- so a multi-megabyte Type stopped snapshots, the
// overlay and every other tool for as long as it ran, and audited as one call.
//
// Both refusals happen before the work is queued, so a zero-value Desktop is
// enough: nothing here reaches the OS.
func TestSyntheticInputIsBounded(t *testing.T) {
	d := &Desktop{}

	if err := d.TypeText(strings.Repeat("a", MaxTypeChars+1)); err == nil {
		t.Error("an over-length Type must be refused before it reaches the engine thread")
	} else if !errors.Is(err, ErrInputTooLarge) {
		t.Errorf("want ErrInputTooLarge, got %v", err)
	}

	points := make([][2]int, MaxBatchItems+1)
	if err := d.ClickMany(points, false); err == nil {
		t.Error("an over-length ClickMany must be refused")
	} else if !errors.Is(err, ErrInputTooLarge) {
		t.Errorf("want ErrInputTooLarge, got %v", err)
	}

	// The limits bound runaway calls, not ordinary ones, so they sit well above
	// real usage. An empty batch stays a no-op rather than becoming an error.
	if err := d.ClickMany(nil, false); err != nil {
		t.Errorf("an empty batch should be a no-op, got %v", err)
	}
}
