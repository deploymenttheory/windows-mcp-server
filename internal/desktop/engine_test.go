//go:build windows && (amd64 || arm64)

package desktop

import (
	"testing"
)

// newTestEngine starts an engine for a test, skipping (not failing) if the
// environment cannot host UI Automation (e.g. a headless session).
func newTestEngine(t *testing.T) *Desktop {
	t.Helper()
	d, err := New(nil, Options{})
	if err != nil {
		t.Skipf("cannot start desktop engine in this environment: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func TestEngineLifecycleAndRoot(t *testing.T) {
	d := newTestEngine(t)
	// The UIA desktop root should have children (the on-screen windows).
	_, childCount, err := d.RootInfo()
	if err != nil {
		t.Fatalf("RootInfo: %v", err)
	}
	if childCount < 0 {
		t.Errorf("unexpected child count %d", childCount)
	}
}

func TestClipboardRoundTrip(t *testing.T) {
	d := newTestEngine(t)
	const want = "windows-mcp engine test ☑ 日本語"
	if err := d.ClipboardSet(want); err != nil {
		t.Fatalf("ClipboardSet: %v", err)
	}
	got, err := d.ClipboardGet()
	if err != nil {
		t.Fatalf("ClipboardGet: %v", err)
	}
	if got != want {
		t.Errorf("clipboard round-trip: got %q, want %q", got, want)
	}
}

func TestScreenshotProducesPNG(t *testing.T) {
	d := newTestEngine(t)
	png, w, h, denom, err := d.Screenshot()
	if err != nil {
		t.Fatalf("Screenshot: %v", err)
	}
	if w <= 0 || h <= 0 || denom < 1 {
		t.Errorf("bad dimensions w=%d h=%d denom=%d", w, h, denom)
	}
	// PNG magic number.
	if len(png) < 8 || string(png[1:4]) != "PNG" {
		t.Errorf("output is not a PNG (len %d)", len(png))
	}
}

func TestDisplaysNonEmpty(t *testing.T) {
	d := newTestEngine(t)
	displays, err := d.Displays()
	if err != nil {
		t.Fatalf("Displays: %v", err)
	}
	if len(displays) == 0 {
		t.Skip("no displays reported (headless)")
	}
	for _, disp := range displays {
		if disp.Bounds.Empty() {
			t.Errorf("display %d has empty bounds", disp.Index)
		}
	}
}

func TestSnapshotCaptures(t *testing.T) {
	d := newTestEngine(t)
	state, err := d.Snapshot(SnapshotOptions{AllWindows: true})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if state == nil {
		t.Fatal("nil state")
	}
	// Label resolution should be consistent with the captured interactive set.
	for _, e := range state.Interactive {
		x, y, ok := d.CoordinatesForLabel(e.Label)
		if !ok || x != e.CenterX || y != e.CenterY {
			t.Errorf("label %d resolution mismatch", e.Label)
			break
		}
	}
}

func TestKeyNameToVK(t *testing.T) {
	cases := map[string]bool{
		"ctrl": true, "CTRL": true, "a": true, "5": true,
		"enter": true, "f13": false, "": false, "notakey": false,
	}
	for name, wantOK := range cases {
		if _, ok := keyNameToVK(name); ok != wantOK {
			t.Errorf("keyNameToVK(%q) ok=%v, want %v", name, ok, wantOK)
		}
	}
}
