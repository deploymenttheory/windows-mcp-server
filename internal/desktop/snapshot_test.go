//go:build windows && (amd64 || arm64)

package desktop

import "testing"

// win builds a WindowInfo with a distinct Handle, which is the identity
// selectTargets de-duplicates on.
func win(handle uintptr, title string, foreground, minimized bool) WindowInfo {
	return WindowInfo{
		Handle:       handle,
		Title:        title,
		IsForeground: foreground,
		Minimized:    minimized,
	}
}

func titles(ws []WindowInfo) []string {
	out := make([]string, len(ws))
	for i, w := range ws {
		out[i] = w.Title
	}
	return out
}

// duplicateHandle returns the first Handle appearing more than once, and whether
// there was one.
func duplicateHandle(ws []WindowInfo) (uintptr, bool) {
	seen := map[uintptr]int{}
	for _, w := range ws {
		seen[w.Handle]++
		if seen[w.Handle] > 1 {
			return w.Handle, true
		}
	}
	return 0, false
}

// TestSelectTargetsFallbackDoesNotDuplicate is the regression guard.
//
// With no foreground window, selectTargets falls back to the topmost
// non-minimized window. The de-duplication loop used to skip by IsForeground,
// but the fallback pick is by definition not foreground — that is why the
// fallback ran — so it was appended twice. Snapshot shares one treeBuilder, and
// therefore one maxTreeNodes budget, across all targets, so the duplicate
// consumed the budget twice and could crowd real elements out of the tree.
func TestSelectTargetsFallbackDoesNotDuplicate(t *testing.T) {
	windows := []WindowInfo{
		win(1, "A", false, false),
		win(2, "B", false, false),
		win(3, "C", false, false),
	}

	got := selectTargets(windows, true)
	if h, dup := duplicateHandle(got); dup {
		t.Errorf("handle %d traversed twice; targets = %v", h, titles(got))
	}
	if len(got) != len(windows) {
		t.Errorf("want each window once (%d), got %d: %v", len(windows), len(got), titles(got))
	}
	// The fallback pick still leads.
	if len(got) > 0 && got[0].Title != "A" {
		t.Errorf("fallback pick should lead, got %q", got[0].Title)
	}
}

// TestSelectTargetsForegroundLeadsAndAppearsOnce covers the unchanged path.
func TestSelectTargetsForegroundLeadsAndAppearsOnce(t *testing.T) {
	windows := []WindowInfo{
		win(1, "A", false, false),
		win(2, "B", true, false), // foreground, deliberately not first
		win(3, "C", false, false),
	}

	got := selectTargets(windows, true)
	if h, dup := duplicateHandle(got); dup {
		t.Errorf("handle %d traversed twice; targets = %v", h, titles(got))
	}
	if len(got) == 0 || got[0].Title != "B" {
		t.Fatalf("foreground window must lead, got %v", titles(got))
	}
	if len(got) != 3 {
		t.Errorf("want all three windows once, got %v", titles(got))
	}
}

// TestSelectTargetsMinimizedExcluded checks minimized windows never join the
// traversal set, in both the foreground and fallback paths.
func TestSelectTargetsMinimizedExcluded(t *testing.T) {
	windows := []WindowInfo{
		win(1, "A", false, true), // minimized
		win(2, "B", false, false),
		win(3, "C", false, true), // minimized
	}
	got := selectTargets(windows, true)
	if len(got) != 1 || got[0].Title != "B" {
		t.Errorf("only the non-minimized window should be traversed, got %v", titles(got))
	}
	if h, dup := duplicateHandle(got); dup {
		t.Errorf("handle %d traversed twice", h)
	}
}

// TestSelectTargetsSingleWindowOnly pins the non-allWindows path: exactly the
// primary, never more.
func TestSelectTargetsSingleWindowOnly(t *testing.T) {
	windows := []WindowInfo{
		win(1, "A", false, false),
		win(2, "B", true, false),
	}
	if got := selectTargets(windows, false); len(got) != 1 || got[0].Title != "B" {
		t.Errorf("want only the foreground window, got %v", titles(got))
	}
	// Same in the fallback path.
	fallback := []WindowInfo{win(1, "A", false, false), win(2, "B", false, false)}
	if got := selectTargets(fallback, false); len(got) != 1 || got[0].Title != "A" {
		t.Errorf("want only the fallback pick, got %v", titles(got))
	}
}

// TestSelectTargetsAllMinimized returns nothing rather than a phantom target.
func TestSelectTargetsAllMinimized(t *testing.T) {
	windows := []WindowInfo{win(1, "A", false, true), win(2, "B", false, true)}
	if got := selectTargets(windows, true); len(got) != 0 {
		t.Errorf("all-minimized should yield no targets, got %v", titles(got))
	}
}

// TestSelectTargetsMinimizedForegroundStillLeads: a minimized foreground window
// is still the primary (it can be restored), and must not be duplicated by the
// allWindows pass — which skips minimized windows anyway.
func TestSelectTargetsMinimizedForegroundStillLeads(t *testing.T) {
	windows := []WindowInfo{
		win(1, "A", false, false),
		win(2, "B", true, true), // foreground but minimized
	}
	got := selectTargets(windows, true)
	if len(got) == 0 || got[0].Title != "B" {
		t.Fatalf("minimized foreground window should still lead, got %v", titles(got))
	}
	if h, dup := duplicateHandle(got); dup {
		t.Errorf("handle %d traversed twice; targets = %v", h, titles(got))
	}
}

// TestSelectTargetsEmpty guards the degenerate input.
func TestSelectTargetsEmpty(t *testing.T) {
	if got := selectTargets(nil, true); len(got) != 0 {
		t.Errorf("no windows should yield no targets, got %v", titles(got))
	}
}
