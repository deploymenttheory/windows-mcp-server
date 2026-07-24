//go:build windows && (amd64 || arm64)

package desktop

import (
	"strings"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
)

// DesktopState is the captured perception of the desktop returned by Snapshot.
// It is also stored on the engine so that label-based interaction (Click/Type
// by label) can resolve labels to screen coordinates.
type DesktopState struct {
	// Foreground is the current foreground window (zero value if none).
	Foreground WindowInfo
	// Windows lists visible, titled top-level windows.
	Windows []WindowInfo
	// Interactive lists the labeled interactive elements, in label order.
	Interactive []LabeledElement
	// TreeText is the human-readable semantic UI tree.
	TreeText string
}

// SnapshotOptions controls what a Snapshot captures.
type SnapshotOptions struct {
	// AllWindows, when true, walks every visible window's tree (subject to the
	// global node budget). When false, only the foreground window is walked,
	// which is faster and usually sufficient.
	AllWindows bool
}

// Snapshot captures the current desktop state: windows, and the labeled
// interactive UI tree of the foreground window (and optionally all windows).
// It stores the result for subsequent label-based interaction.
func (d *Desktop) Snapshot(opts SnapshotOptions) (*DesktopState, error) {
	var state *DesktopState
	err := d.Do(func() error {
		windows, e := d.topLevelWindows()
		if e != nil {
			return e
		}
		fg, hasFg := d.foregroundWindowInfo()
		if hasFg && d.overlay != nil && !fg.Minimized {
			// Show a green hue around the app currently in focus.
			d.overlay.highlightWindow(fg.Rect)
		}

		targets := selectTargets(windows, opts.AllWindows)

		walker, e := d.uia.automation.Get_ControlViewWalker()
		if e != nil {
			return e
		}
		defer walker.Release()

		tb := &treeBuilder{walker: walker}
		for _, w := range targets {
			el, e := d.elementForWindow(foundation.HWND(w.Handle))
			if e != nil || el == nil {
				continue
			}
			tb.visitWindow(el, w)
			el.Release()
			if tb.nodes >= maxTreeNodes {
				break
			}
		}

		state = &DesktopState{
			Foreground:  fg,
			Windows:     windows,
			Interactive: tb.interactive,
			TreeText:    strings.Join(tb.lines, "\n"),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	d.stateMu.Lock()
	d.lastState = state
	d.stateMu.Unlock()
	return state, nil
}

// selectTargets orders windows for traversal: the foreground window first, then
// (when allWindows) the remaining non-minimized windows.
func selectTargets(windows []WindowInfo, allWindows bool) []WindowInfo {
	var fg *WindowInfo
	for i := range windows {
		if windows[i].IsForeground {
			fg = &windows[i]
			break
		}
	}

	var targets []WindowInfo
	if fg != nil {
		targets = append(targets, *fg)
	} else if len(windows) > 0 {
		// No foreground window (e.g. focus in transition): fall back to the
		// topmost non-minimized window so a snapshot still captures something.
		for i := range windows {
			if !windows[i].Minimized {
				targets = append(targets, windows[i])
				fg = &windows[i]
				break
			}
		}
	}
	if !allWindows {
		return targets
	}
	for i := range windows {
		if windows[i].IsForeground || windows[i].Minimized {
			continue
		}
		targets = append(targets, windows[i])
	}
	return targets
}

// CoordinatesForLabel resolves a label from the most recent Snapshot to a click
// point. It is safe to call from any goroutine.
func (d *Desktop) CoordinatesForLabel(label int) (x, y int, ok bool) {
	d.stateMu.Lock()
	defer d.stateMu.Unlock()
	if d.lastState == nil {
		return 0, 0, false
	}
	for _, e := range d.lastState.Interactive {
		if e.Label == label {
			return e.CenterX, e.CenterY, true
		}
	}
	return 0, 0, false
}

// LastState returns the most recent Snapshot, or nil if none has been taken.
func (d *Desktop) LastState() *DesktopState {
	d.stateMu.Lock()
	defer d.stateMu.Unlock()
	return d.lastState
}
