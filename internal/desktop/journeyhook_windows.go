//go:build windows && (amd64 || arm64)

package desktop

import (
	"errors"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/threading"
	km "github.com/deploymenttheory/go-bindings-win32/bindings/win32/ui/input/keyboardandmouse"
	wm "github.com/deploymenttheory/go-bindings-win32/bindings/win32/ui/windowsandmessaging"
)

// This file is the low-level capture half of the journey recorder: it installs
// WH_MOUSE_LL and WH_KEYBOARD_LL hooks on a dedicated, thread-locked message-pump
// thread and turns the raw callbacks into rawInput values on a channel.
//
// The hook procedures must be fast and must never touch COM or block: the OS calls
// them synchronously on this thread for every input event on the desktop, so any
// stall stalls all input. They only decode the event and do a non-blocking send,
// dropping on overflow (the same discipline the overlay uses). All enrichment —
// the UIA hit-test, the password check — happens later, on the engine STA thread.

// Windows message constants for the input we capture.
const (
	wmLButtonDown = 0x0201
	wmRButtonDown = 0x0204
	wmMButtonDown = 0x0207
	wmKeyDown     = 0x0100
	wmSysKeyDown  = 0x0104
	wmQuit        = 0x0012
)

// rawInputKind classifies a captured event.
type rawInputKind int

const (
	rawMouseDown rawInputKind = iota
	rawKeyDown
)

// rawInput is one decoded hook event, engine-neutral and COM-free.
type rawInput struct {
	kind   rawInputKind
	x, y   int    // screen point (mouse)
	button string // left | right | middle (mouse)
	vk     uint32 // virtual-key code (keyboard)
	scan   uint32 // scan code (keyboard)
	shift  bool   // shift held at keystroke time
	caps   bool   // caps-lock toggled at keystroke time
	timeMS uint32 // event time, for double-click detection
}

// Virtual-key codes for the modifier state sampled at each keystroke.
const (
	vkShift   = 0x10
	vkCapital = 0x14
)

// hookSession owns one pair of installed hooks and the thread they run on.
type hookSession struct {
	events chan rawInput
	tid    uint32     // the hook thread's id, for PostThreadMessage(WM_QUIT)
	ready  chan error // startup handshake
	done   chan struct{}
}

// Only one recording session runs at a time. The hook procedures are package-level
// syscall callbacks (a hook proc cannot carry Go closure state), so they reach the
// active session through this pointer, guarded by the mutex. It is set while hooks
// are installed and cleared when they are removed.
var (
	hookMu      sync.Mutex
	activeHooks *hookSession

	mouseHookProc = syscall.NewCallback(lowLevelMouseProc)
	keyHookProc   = syscall.NewCallback(lowLevelKeyboardProc)
)

// errRecordingActive reports a second recording session while one is already
// running; only one set of hooks may be installed at a time.
var errRecordingActive = errors.New("an input recording session is already active")

// startInputHooks installs the low-level hooks on a fresh pumped thread and returns
// the session. Only one may be active; a second call errors.
func startInputHooks() (*hookSession, error) {
	hookMu.Lock()
	if activeHooks != nil {
		hookMu.Unlock()
		return nil, errRecordingActive
	}
	s := &hookSession{
		events: make(chan rawInput, 256),
		ready:  make(chan error, 1),
		done:   make(chan struct{}),
	}
	activeHooks = s
	hookMu.Unlock()

	go s.run()
	if err := <-s.ready; err != nil {
		hookMu.Lock()
		activeHooks = nil
		hookMu.Unlock()
		return nil, err
	}
	return s, nil
}

// run locks the thread, installs both hooks, and pumps messages with a blocking
// GetMessage loop — which is what services low-level hooks — until WM_QUIT.
func (s *hookSession) run() {
	runtime.LockOSThread()
	// Deliberately never unlocked: this OS thread owns the hooks and their message
	// pump for its whole life, mirroring the overlay and COM threads.
	defer close(s.done)

	s.tid = threading.GetCurrentThreadId()

	mouseHook, err := wm.SetWindowsHookEx(wm.WH_MOUSE_LL, wm.HOOKPROC(mouseHookProc), 0, 0)
	if err != nil {
		s.ready <- err
		return
	}
	keyHook, err := wm.SetWindowsHookEx(wm.WH_KEYBOARD_LL, wm.HOOKPROC(keyHookProc), 0, 0)
	if err != nil {
		_ = wm.UnhookWindowsHookEx(mouseHook)
		s.ready <- err
		return
	}
	defer func() {
		_ = wm.UnhookWindowsHookEx(keyHook)
		_ = wm.UnhookWindowsHookEx(mouseHook)
	}()
	s.ready <- nil

	var msg wm.MSG
	for {
		// GetMessage blocks until a message arrives; it returns an error on WM_QUIT
		// (which posts a 0 return in the Win32 API). Either way, exit the loop.
		if err := wm.GetMessage(&msg, 0, 0, 0); err != nil {
			return
		}
		if msg.Message == wmQuit {
			return
		}
	}
}

// stop asks the pump thread to exit and waits for it. Idempotent.
func (s *hookSession) stop() {
	hookMu.Lock()
	if activeHooks == s {
		activeHooks = nil
	}
	hookMu.Unlock()
	if s.tid != 0 {
		_ = wm.PostThreadMessage(s.tid, wmQuit, 0, 0)
	}
	<-s.done
}

// deliver sends a decoded event to the active session without blocking. If the
// buffer is full the event is dropped — recording must never stall live input.
func deliver(in rawInput) {
	hookMu.Lock()
	s := activeHooks
	hookMu.Unlock()
	if s == nil {
		return
	}
	select {
	case s.events <- in:
	default:
	}
}

// llkhfInjected is LLKHF_INJECTED: the event was generated by SendInput rather
// than by a physical key.
const llkhfInjected = 0x10

// lowLevelMouseProc is the WH_MOUSE_LL callback. It records only button-downs.
func lowLevelMouseProc(code int32, wParam, lParam uintptr) uintptr {
	if code >= 0 {
		var button string
		msg := uint32(wParam) //nolint:gosec // wParam carries the window-message id, which fits uint32
		switch msg {
		case wmLButtonDown:
			button = "left"
		case wmRButtonDown:
			button = "right"
		case wmMButtonDown:
			button = "middle"
		}
		if button != "" {
			//nolint:govet // lParam is an OS-owned pointer to the hook struct, valid for this callback; it must be taken as uintptr so Go's GC does not track a non-Go pointer.
			ms := (*wm.MSLLHOOKSTRUCT)(unsafe.Pointer(lParam))
			deliver(rawInput{
				kind: rawMouseDown, button: button,
				x: int(ms.Pt.X), y: int(ms.Pt.Y), timeMS: ms.Time,
			})
		}
	}
	return uintptr(wm.CallNextHookEx(0, code, foundation.WPARAM(wParam), foundation.LPARAM(lParam)))
}

// lowLevelKeyboardProc is the WH_KEYBOARD_LL callback. It records key-downs.
func lowLevelKeyboardProc(code int32, wParam, lParam uintptr) uintptr {
	msg := uint32(wParam) //nolint:gosec // wParam carries the window-message id, which fits uint32
	if code >= 0 && (msg == wmKeyDown || msg == wmSysKeyDown) {
		//nolint:govet // lParam is an OS-owned pointer to the hook struct, valid for this callback; it must be taken as uintptr so Go's GC does not track a non-Go pointer.
		kb := (*wm.KBDLLHOOKSTRUCT)(unsafe.Pointer(lParam))
		// Skip synthetic input. A recorder is meant to capture what a person did,
		// and SendInput events carry LLKHF_INJECTED; without this filter, a journey
		// recorded while an agent session is live captures the agent's own
		// keystrokes -- including a credential injection, whose whole design is that
		// the secret is typed and never written down.
		if kb.Flags&llkhfInjected != 0 {
			return uintptr(wm.CallNextHookEx(0, code, foundation.WPARAM(wParam), foundation.LPARAM(lParam)))
		}
		deliver(rawInput{
			kind: rawKeyDown, vk: kb.VkCode, scan: kb.ScanCode, timeMS: kb.Time,
			// Sample the modifier state now, on the hook thread, so translation later
			// sees the shift/caps state as it was at the keystroke. GetAsyncKeyState
			// returns an int16 whose high bit (a negative value) means the key is down;
			// for caps-lock the low bit is the toggle state.
			shift: km.GetAsyncKeyState(vkShift) < 0,
			caps:  km.GetAsyncKeyState(vkCapital)&0x0001 != 0,
		})
	}
	return uintptr(wm.CallNextHookEx(0, code, foundation.WPARAM(wParam), foundation.LPARAM(lParam)))
}
