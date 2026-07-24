//go:build windows && (amd64 || arm64)

package desktop

import (
	"encoding/binary"
	"syscall"
	"time"

	win32 "github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/graphics/dwm"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/ui/accessibility"
	wm "github.com/deploymenttheory/go-bindings-win32/bindings/win32/ui/windowsandmessaging"
)

// dwmwaCloaked is DWMWA_CLOAKED for DwmGetWindowAttribute.
const dwmwaCloaked = uint32(14)

// isCloaked reports whether a window is DWM-cloaked (hidden by the compositor —
// e.g. a UWP app on another virtual desktop, or a suspended app's ghost window).
// Such windows pass IsWindowVisible but are not really on screen.
func isCloaked(hwnd foundation.HWND) bool {
	var buf [4]byte
	if err := dwm.DwmGetWindowAttribute(hwnd, dwmwaCloaked, buf[:]); err != nil {
		return false // attribute unavailable: treat as not cloaked
	}
	return binary.LittleEndian.Uint32(buf[:]) != 0
}

// foregroundWindow returns the current foreground window handle, retrying
// briefly because GetForegroundWindow transiently returns NULL during focus
// transitions (e.g. just after launching an app). STA thread only.
func foregroundWindow() foundation.HWND {
	for range 3 {
		if fg := wm.GetForegroundWindow(); fg != 0 {
			return fg
		}
		time.Sleep(100 * time.Millisecond)
	}
	return 0
}

// WindowInfo describes a top-level window.
type WindowInfo struct {
	Handle       uintptr
	Title        string
	ClassName    string
	Rect         Rect
	ProcessID    uint32
	Minimized    bool
	IsForeground bool
}

// enumWindowsSink is the collection target for the shared EnumWindows callback.
// It is only ever read/written on the engine STA thread (all engine work is
// serialized there), so no synchronization is needed and the callback can be
// registered once rather than per call (syscall.NewCallback allocations cannot
// be freed).
var enumWindowsSink *[]foundation.HWND

var enumWindowsCallback = syscall.NewCallback(func(hwnd uintptr, _ uintptr) uintptr {
	if enumWindowsSink != nil {
		*enumWindowsSink = append(*enumWindowsSink, foundation.HWND(hwnd))
	}
	return 1 // continue enumeration
})

// getWindowText returns a window's title text.
func getWindowText(hwnd foundation.HWND) string {
	n, err := wm.GetWindowTextLength(hwnd)
	if err != nil || n <= 0 {
		return ""
	}
	buf := make([]uint16, n+1)
	got, err := wm.GetWindowText(hwnd, foundation.PWSTR(&buf[0]), int32(len(buf)))
	if err != nil || got <= 0 {
		return ""
	}
	return win32.UTF16ToString(&buf[0])
}

// getClassName returns a window's class name.
func getClassName(hwnd foundation.HWND) string {
	buf := make([]uint16, 256)
	got, err := wm.GetClassName(hwnd, foundation.PWSTR(&buf[0]), int32(len(buf)))
	if err != nil || got <= 0 {
		return ""
	}
	return win32.UTF16ToString(&buf[0])
}

func windowRect(hwnd foundation.HWND) Rect {
	var r foundation.RECT
	if err := wm.GetWindowRect(hwnd, &r); err != nil {
		return Rect{}
	}
	return Rect{Left: int(r.Left), Top: int(r.Top), Right: int(r.Right), Bottom: int(r.Bottom)}
}

func windowProcessID(hwnd foundation.HWND) uint32 {
	var pid uint32
	wm.GetWindowThreadProcessId(hwnd, &pid)
	return pid
}

// topLevelWindows enumerates visible, titled top-level windows. It must run on
// the engine STA thread.
func (d *Desktop) topLevelWindows() ([]WindowInfo, error) {
	var handles []foundation.HWND
	enumWindowsSink = &handles
	err := wm.EnumWindows(wm.WNDENUMPROC(enumWindowsCallback), 0)
	enumWindowsSink = nil
	if err != nil {
		return nil, err
	}

	fg := foregroundWindow()

	windows := make([]WindowInfo, 0, len(handles))
	for _, h := range handles {
		if !wm.IsWindowVisible(h) {
			continue
		}
		if isCloaked(h) {
			continue // ghost/other-desktop window
		}
		title := getWindowText(h)
		if title == "" {
			continue
		}
		rect := windowRect(h)
		if rect.Empty() {
			continue
		}
		windows = append(windows, WindowInfo{
			Handle:       uintptr(h),
			Title:        title,
			ClassName:    getClassName(h),
			Rect:         rect,
			ProcessID:    windowProcessID(h),
			Minimized:    wm.IsIconic(h),
			IsForeground: h == fg,
		})
	}
	return windows, nil
}

// TopLevelWindows returns the visible, titled top-level windows.
func (d *Desktop) TopLevelWindows() ([]WindowInfo, error) {
	var out []WindowInfo
	err := d.Do(func() error {
		w, e := d.topLevelWindows()
		out = w
		return e
	})
	return out, err
}

// foregroundWindowInfo returns info about the current foreground window (STA
// thread).
func (d *Desktop) foregroundWindowInfo() (WindowInfo, bool) {
	fg := foregroundWindow()
	if fg == 0 {
		return WindowInfo{}, false
	}
	title := getWindowText(fg)
	return WindowInfo{
		Handle:       uintptr(fg),
		Title:        title,
		ClassName:    getClassName(fg),
		Rect:         windowRect(fg),
		ProcessID:    windowProcessID(fg),
		Minimized:    wm.IsIconic(fg),
		IsForeground: true,
	}, true
}

// elementForWindow returns the UIA element for a window handle. Caller releases
// it. STA thread only.
func (d *Desktop) elementForWindow(hwnd foundation.HWND) (*accessibility.IUIAutomationElement, error) {
	return d.uia.automation.ElementFromHandle(hwnd)
}
