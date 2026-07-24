//go:build windows && (amd64 || arm64)

package desktop

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/threading"
	wm "github.com/deploymenttheory/go-bindings-win32/bindings/win32/ui/windowsandmessaging"
)

// asfwAny is ASFW_ANY for AllowSetForegroundWindow (allow any process).
const asfwAny = ^uint32(0)

// findWindowByTitle returns the first visible top-level window whose title
// contains the given substring (case-insensitive). STA thread only.
func (d *Desktop) findWindowByTitle(substr string) (WindowInfo, bool) {
	windows, err := d.topLevelWindows()
	if err != nil {
		return WindowInfo{}, false
	}
	needle := strings.ToLower(strings.TrimSpace(substr))
	for _, w := range windows {
		if strings.Contains(strings.ToLower(w.Title), needle) {
			return w, true
		}
	}
	return WindowInfo{}, false
}

// bringToForeground activates a window using the AttachThreadInput technique so
// Windows grants the foreground change even though the calling process is not
// the current foreground app. STA thread only.
func bringToForeground(hwnd foundation.HWND) {
	if wm.IsIconic(hwnd) {
		wm.ShowWindow(hwnd, wm.SW_RESTORE)
	}
	fg := wm.GetForegroundWindow()
	if fg == hwnd {
		return
	}

	cur := threading.GetCurrentThreadId()
	var fgProc uint32
	fgThread := wm.GetWindowThreadProcessId(fg, &fgProc)
	var tgtProc uint32
	tgtThread := wm.GetWindowThreadProcessId(hwnd, &tgtProc)

	if fgThread != 0 && fgThread != cur {
		threading.AttachThreadInput(cur, fgThread, true)
		defer threading.AttachThreadInput(cur, fgThread, false)
	}
	if tgtThread != 0 && tgtThread != cur && tgtThread != fgThread {
		threading.AttachThreadInput(cur, tgtThread, true)
		defer threading.AttachThreadInput(cur, tgtThread, false)
	}

	_ = wm.AllowSetForegroundWindow(asfwAny)
	_ = wm.BringWindowToTop(hwnd)
	wm.ShowWindow(hwnd, wm.SW_SHOW)
	wm.SetForegroundWindow(hwnd)
}

// ActivateWindow brings the first window matching titleSubstr to the foreground
// and (if overlays are on) highlights it. Returns the activated window.
func (d *Desktop) ActivateWindow(titleSubstr string) (WindowInfo, error) {
	var result WindowInfo
	var found bool
	err := d.Do(func() error {
		w, ok := d.findWindowByTitle(titleSubstr)
		if !ok {
			return fmt.Errorf("no window matching %q", titleSubstr)
		}
		bringToForeground(foundation.HWND(w.Handle))
		result, found = w, true
		if d.overlay != nil {
			d.overlay.highlightWindow(w.Rect)
		}
		return nil
	})
	if err != nil {
		return WindowInfo{}, err
	}
	if !found {
		return WindowInfo{}, fmt.Errorf("no window matching %q", titleSubstr)
	}
	return result, nil
}

// ResizeWindow moves and resizes the first window matching titleSubstr.
func (d *Desktop) ResizeWindow(titleSubstr string, x, y, width, height int) (WindowInfo, error) {
	var result WindowInfo
	err := d.Do(func() error {
		w, ok := d.findWindowByTitle(titleSubstr)
		if !ok {
			return fmt.Errorf("no window matching %q", titleSubstr)
		}
		hwnd := foundation.HWND(w.Handle)
		if wm.IsIconic(hwnd) {
			wm.ShowWindow(hwnd, wm.SW_RESTORE)
		}
		if err := wm.MoveWindow(hwnd, int32(x), int32(y), int32(width), int32(height), true); err != nil {
			return fmt.Errorf("MoveWindow: %w", err)
		}
		w.Rect = Rect{Left: x, Top: y, Right: x + width, Bottom: y + height}
		result = w
		if d.overlay != nil {
			d.overlay.highlightWindow(w.Rect)
		}
		return nil
	})
	if err != nil {
		return WindowInfo{}, err
	}
	return result, nil
}

// LaunchApp starts an application by name via the shell (Start-Process), which
// resolves apps on PATH and registered app execution aliases (e.g. "notepad",
// "msedge"). It waits briefly and returns the launched window if one appears.
func (d *Desktop) LaunchApp(ctx context.Context, name string) (string, error) {
	// Single-quote and escape for PowerShell.
	quoted := "'" + strings.ReplaceAll(name, "'", "''") + "'"
	res, err := d.RunPowerShell(ctx, "Start-Process "+quoted, 20*time.Second)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("Start-Process failed: %s", strings.TrimSpace(res.Output))
	}
	return name, nil
}

// LaunchExecutable starts an executable directly (detached), returning its PID.
func (d *Desktop) LaunchExecutable(path string, args []string, cwd string) (int, error) {
	if _, err := os.Stat(path); err != nil {
		return 0, fmt.Errorf("executable not found: %w", err)
	}
	cmd := exec.Command(path, args...)
	if cwd != "" {
		cmd.Dir = cwd
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("failed to start executable: %w", err)
	}
	pid := cmd.Process.Pid
	// Release the process so it keeps running independently of the server.
	_ = cmd.Process.Release()
	return pid, nil
}
