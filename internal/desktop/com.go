//go:build windows && (amd64 || arm64)

// Package desktop is the Windows automation engine underneath the MCP tools. It
// reimplements the capabilities of the Python Windows-MCP project (UI
// Automation tree walking, synthetic input, screenshots, window management,
// PowerShell execution, WMI-backed system data) on top of the
// deploymenttheory go-bindings-win32 and go-bindings-wmi SDKs.
//
// # COM threading model
//
// UI Automation and much of the Win32 input/window surface are thread-affine:
// COM objects created in one apartment must be used from that apartment, and
// foreground/focus operations are tied to a specific thread. The engine
// therefore owns a single dedicated OS thread (locked with
// runtime.LockOSThread) initialized as an STA, and funnels every COM/UIA/input
// call through it via Do. This mirrors the single-threaded traversal the Python
// implementation relies on to avoid COM apartment deadlocks.
package desktop

import (
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync"

	win32 "github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/com"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/ui/hidpi"
)

// coInitApartmentThreaded is the STA flag for CoInitializeEx. CoInitializeEx
// takes a raw uint32; the binding's COINIT enum value is reproduced here.
const coInitApartmentThreaded = uint32(com.COINIT_APARTMENTTHREADED)

// ErrClosed is returned when work is submitted to a closed engine.
var ErrClosed = errors.New("desktop: engine is closed")

// job is a unit of work executed on the engine's dedicated STA thread.
type job struct {
	fn   func() error
	done chan error
}

// Desktop is the Windows automation engine. It is safe for concurrent use by
// multiple goroutines: all Win32/COM work is serialized onto one STA thread.
// Construct it with New and release it with Close.
type Desktop struct {
	logger *slog.Logger

	jobs chan job
	quit chan struct{}

	// uia holds the UI Automation client, created on the STA thread during
	// startup. It is only touched from within Do.
	uia *uiaClient

	// overlay draws visual-feedback overlays (green window hue, orange click
	// flash) for screen capture. It runs on its own thread and is nil when
	// overlays are disabled.
	overlay *overlayManager

	// recorder captures the whole session to a video file. Runs on its own
	// goroutine; nil when recording is disabled.
	recorder *recorder

	// stateMu guards lastState, the most recent Snapshot. Label-based
	// interaction (Click/Type by label) resolves against it, so it is read from
	// caller goroutines as well as written after a snapshot.
	stateMu   sync.Mutex
	lastState *DesktopState

	// wmi is the lazily-initialized WMI worker (own thread), guarded by wmiMu.
	wmiMu sync.Mutex
	wmi   *wmiWorker
}

// Options configures the engine.
type Options struct {
	// Overlay enables visual-feedback overlays (green highlight around the
	// active window, orange flash at click points) for screen capture and video
	// recording.
	Overlay bool

	// Record, when its Dir is set, records the whole session to a video file so
	// every session is tracked regardless of persona.
	Record RecorderOptions
}

// New starts the engine: it spins up the dedicated STA thread, makes the
// process per-monitor-DPI aware, initializes COM, and creates the UI Automation
// client. It returns once startup has completed (or failed).
func New(logger *slog.Logger, opts Options) (*Desktop, error) {
	if logger == nil {
		logger = slog.Default()
	}
	d := &Desktop{
		logger: logger,
		jobs:   make(chan job),
		quit:   make(chan struct{}),
	}
	ready := make(chan error, 1)
	go d.loop(ready)
	if err := <-ready; err != nil {
		close(d.quit)
		return nil, err
	}

	if opts.Overlay {
		ov, err := newOverlayManager(logger)
		if err != nil {
			// Overlays are optional decoration; log and continue without them.
			logger.Warn("visual overlays disabled: failed to start", "error", err)
		} else {
			d.overlay = ov
		}
	}

	if opts.Record.Dir != "" {
		rec, err := startRecorder(opts.Record, logger)
		if err != nil {
			// Recording is optional; log and continue without it.
			logger.Warn("session recording disabled: failed to start", "error", err)
		} else {
			d.recorder = rec
			logger.Info("session recording started", "file", rec.videoPath)
		}
	}
	return d, nil
}

// RecordingStatus returns the session recorder's status and whether recording
// is active.
func (d *Desktop) RecordingStatus() (RecordingStatus, bool) {
	if d.recorder == nil {
		return RecordingStatus{}, false
	}
	return d.recorder.status(), true
}

// MarkRecording adds a labeled marker to the session recording timeline, if
// recording is active.
func (d *Desktop) MarkRecording(label string) bool {
	if d.recorder == nil {
		return false
	}
	d.recorder.mark(label)
	return true
}

// loop runs on the dedicated OS thread for the lifetime of the engine. It
// performs thread-affine startup, signals readiness, then serves jobs until
// Close.
func (d *Desktop) loop(ready chan<- error) {
	// The engine thread must never be reused by the Go scheduler for other
	// goroutines: COM apartment state and foreground-window affinity live on it.
	// We deliberately do NOT UnlockOSThread, so that when loop returns the
	// runtime retires this thread instead of recycling its (now-uninitialized)
	// COM state.
	runtime.LockOSThread()

	// Per-Monitor-V2 DPI awareness must be established before any window or
	// coordinate work, otherwise the OS virtualizes coordinates and every
	// click/screenshot is offset on high-DPI displays. It is process-wide and
	// best-effort: a failure here (e.g. already set by a manifest) is non-fatal.
	if err := hidpi.SetProcessDpiAwarenessContext(hidpi.DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2); err != nil {
		d.logger.Warn("failed to set per-monitor-v2 DPI awareness", "error", err)
	}

	if _, err := com.CoInitializeEx(coInitApartmentThreaded); err != nil {
		ready <- fmt.Errorf("desktop: CoInitializeEx failed: %w", err)
		return
	}
	defer com.CoUninitialize()

	// Establish process-wide COM security with impersonation. This is honored
	// only from the first thread to initialize COM in the process — this one —
	// and must happen before any COM object is created. Without it, out-of-proc
	// COM (notably WMI ExecQuery) fails with WBEM_E_ACCESS_DENIED. Non-fatal:
	// in-process UIA does not require it.
	if err := com.CoInitializeSecurity(
		security.PSECURITY_DESCRIPTOR(0), -1, nil,
		com.RPC_C_AUTHN_LEVEL_DEFAULT, com.RPC_C_IMP_LEVEL_IMPERSONATE,
		nil, uint32(com.EOAC_NONE),
	); err != nil {
		d.logger.Warn("CoInitializeSecurity failed; WMI queries may be denied", "error", err)
	}

	uia, err := newUIAClient()
	if err != nil {
		ready <- fmt.Errorf("desktop: UI Automation init failed: %w", err)
		return
	}
	d.uia = uia
	defer d.uia.close()

	ready <- nil

	for {
		select {
		case j := <-d.jobs:
			j.done <- safeCall(j.fn)
		case <-d.quit:
			return
		}
	}
}

// Do runs fn on the engine's dedicated STA thread and returns its error. It is
// the only sanctioned way to touch COM/UIA/input state. Calls are serialized:
// fn runs to completion before the next queued job starts.
func (d *Desktop) Do(fn func() error) error {
	j := job{fn: fn, done: make(chan error, 1)}
	select {
	case d.jobs <- j:
		return <-j.done
	case <-d.quit:
		return ErrClosed
	}
}

// Close shuts down the engine thread. After Close, Do returns ErrClosed.
func (d *Desktop) Close() error {
	if d.recorder != nil {
		d.recorder.close()
	}
	if d.overlay != nil {
		d.overlay.close()
	}
	d.closeWMI()
	select {
	case <-d.quit:
		// already closed
	default:
		close(d.quit)
	}
	return nil
}

// Logger returns the engine's logger.
func (d *Desktop) Logger() *slog.Logger { return d.logger }

// uiaClient exposes the UI Automation root for engine internals.
func (d *Desktop) client() *uiaClient { return d.uia }

// safeCall runs fn, converting a panic into an error so a single bad call
// cannot take down the engine thread.
func safeCall(fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("desktop: panic in engine job: %v", r)
		}
	}()
	return fn()
}

// hresultError wraps a failing HRESULT with context.
func hresultError(what string, hr win32.HRESULT) error {
	return fmt.Errorf("%s: hresult 0x%08X", what, uint32(hr))
}
