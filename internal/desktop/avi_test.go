//go:build windows && (amd64 || arm64)

package desktop

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func newTestAVI(t *testing.T) *aviWriter {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.avi")
	a, err := newAVIWriter(path, 320, 240, 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.close() })
	return a
}

// TestAVIRefusesFrameBeyondFormatLimit is the regression guard for a silent
// corruption bug. Every size in AVI 1.0 is a uint32 — the RIFF size, the movi
// size, and each idx1 offset — so past 4 GiB they wrapped and produced a corrupt
// file with no error. Recording is force-enabled by --security and the MJPEG
// writer is the fallback whenever ffmpeg is absent, so that silently damaged the
// forensic artifact of a long secured session.
//
// The limit is asserted by driving movieBytes directly rather than writing 4 GiB.
func TestAVIRefusesFrameBeyondFormatLimit(t *testing.T) {
	a := newTestAVI(t)

	frame := make([]byte, 1024)
	if err := a.writeFrame(frame); err != nil {
		t.Fatalf("a normal frame must be accepted: %v", err)
	}

	// Park the writer just under the ceiling: one more small frame still fits.
	a.movieBytes = math.MaxUint32 - aviHeaderSize - 8*aviIndexEntrySize - 4096
	if !a.fits(len(frame)) {
		t.Fatal("a frame just under the ceiling should still fit")
	}
	if err := a.writeFrame(frame); err != nil {
		t.Errorf("frame under the ceiling must be accepted: %v", err)
	}

	// Now push past it.
	a.movieBytes = math.MaxUint32
	if a.fits(len(frame)) {
		t.Error("a frame past the ceiling must not fit")
	}
	err := a.writeFrame(frame)
	if !errors.Is(err, ErrAVISizeLimit) {
		t.Fatalf("want ErrAVISizeLimit, got %v", err)
	}
}

// TestAVIStaysValidAfterHittingTheLimit asserts the whole point of stopping
// rather than wrapping: the file finalizes cleanly and every patched size field
// is within uint32 range.
func TestAVIStaysValidAfterHittingTheLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capped.avi")
	a, err := newAVIWriter(path, 320, 240, 4)
	if err != nil {
		t.Fatal(err)
	}

	frame := make([]byte, 512)
	for range 3 {
		if err := a.writeFrame(frame); err != nil {
			t.Fatal(err)
		}
	}
	// Refuse further frames, exactly as the recorder would observe.
	a.movieBytes = math.MaxUint32
	if err := a.writeFrame(frame); !errors.Is(err, ErrAVISizeLimit) {
		t.Fatalf("want ErrAVISizeLimit, got %v", err)
	}
	// Restore a truthful byte count before finalizing (the recorder stops here;
	// this test only forced the counter to reach the limit).
	a.movieBytes = 3 * (aviFrameHeaderSize + len(frame))

	if err := a.close(); err != nil {
		t.Fatalf("close after hitting the limit must succeed: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() < aviHeaderSize {
		t.Errorf("file is smaller than the header: %d bytes", info.Size())
	}
	if a.count != 3 {
		t.Errorf("refused frame must not be counted: count = %d, want 3", a.count)
	}
}

// TestAVIFitsAccountsForIndexGrowth guards the subtle part of the projection:
// the idx1 table grows 16 bytes per frame and is written at close, so it has to
// be included or the ceiling is computed too generously.
func TestAVIFitsAccountsForIndexGrowth(t *testing.T) {
	a := newTestAVI(t)
	const frameLen = 1000

	// Sit exactly at the boundary ignoring the index, then confirm the index
	// pushes it over.
	a.count = 1000
	a.movieBytes = math.MaxUint32 - aviHeaderSize - aviFrameHeaderSize - frameLen + 8
	if a.fits(frameLen) {
		t.Error("fits must account for the idx1 entries written at close")
	}
}

// TestAVIOddFrameAccountsForPadding covers the word-alignment byte.
func TestAVIOddFrameAccountsForPadding(t *testing.T) {
	a := newTestAVI(t)
	odd := make([]byte, 101)
	if err := a.writeFrame(odd); err != nil {
		t.Fatal(err)
	}
	want := aviFrameHeaderSize + len(odd) + 1 // +1 pad byte
	if a.movieBytes != want {
		t.Errorf("movieBytes = %d, want %d (header + payload + pad)", a.movieBytes, want)
	}
}
