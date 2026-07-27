//go:build windows && (amd64 || arm64)

// Visual feedback overlays for screen capture and video recording.
//
// The overlay manager draws click-through, top-most, no-activate layered
// windows so that a viewer (or a recording) can see what the automation is
// doing: a translucent green border around a window when it is activated or
// targeted, and a brief orange ring at each click point. Overlays never
// intercept input (WS_EX_TRANSPARENT) and never take focus (WS_EX_NOACTIVATE),
// so they cannot perturb the automation they visualize.
//
// Rendering is push-based via UpdateLayeredWindow with a premultiplied-BGRA DIB,
// so no WM_PAINT loop is required; a light message pump keeps the windows
// well-behaved and processes teardown. All window/GDI objects live on one
// dedicated OS thread (windows are thread-affine).
package desktop

import (
	"log/slog"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	win32 "github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	gdi "github.com/deploymenttheory/go-bindings-win32/bindings/win32/graphics/gdi"
	wm "github.com/deploymenttheory/go-bindings-win32/bindings/win32/ui/windowsandmessaging"
)

const (
	overlayClassName      = "WindowsMCPOverlay"
	highlightBorderPx     = 6
	highlightAlpha        = 150
	highlightTTL          = 900 * time.Millisecond
	clickRadiusPx         = 26
	clickRingThicknessPx  = 7
	clickAlpha            = 190
	clickTTL              = 450 * time.Millisecond
	bannerHeightPx        = 76
	bannerFontPx          = 30
	overlayExLayeredFlags = wm.WS_EX_LAYERED | wm.WS_EX_TRANSPARENT | wm.WS_EX_TOPMOST | wm.WS_EX_TOOLWINDOW | wm.WS_EX_NOACTIVATE
)

// overlayCmdKind selects what an overlay command draws.
type overlayCmdKind int

const (
	cmdClick overlayCmdKind = iota
	cmdHighlight
	cmdSecurityBanner
	cmdDismissBanner
)

type overlayCmd struct {
	kind overlayCmdKind
	rect Rect   // highlight: window rect; click: derived from center point
	text string // security banner text
}

// activeOverlay is one on-screen layered window and its GDI backing, tracked so
// it can be torn down when it expires.
type activeOverlay struct {
	hwnd       foundation.HWND
	dc         gdi.HDC
	bitmap     gdi.HBITMAP
	expiry     time.Time
	persistent bool // security banner: never expired by expire()
}

// overlayManager owns the overlay thread and its windows.
type overlayManager struct {
	logger *slog.Logger
	cmds   chan overlayCmd
	quit   chan struct{}

	hinstance foundation.HINSTANCE
	highlight *activeOverlay
	clicks    []*activeOverlay
	banner    *activeOverlay
}

// wndProcCallback is the shared window procedure. Layered windows updated via
// UpdateLayeredWindow need no custom painting, so it just defers to the OS.
var wndProcCallback = syscall.NewCallback(func(hwnd foundation.HWND, msg uint32, wp foundation.WPARAM, lp foundation.LPARAM) foundation.LRESULT {
	return wm.DefWindowProc(hwnd, msg, wp, lp)
})

// newOverlayManager starts the overlay thread. If Win32 setup fails, it returns
// an error and the caller should proceed without overlays.
func newOverlayManager(logger *slog.Logger) (*overlayManager, error) {
	m := &overlayManager{
		logger: logger,
		cmds:   make(chan overlayCmd, 64),
		quit:   make(chan struct{}),
	}
	ready := make(chan error, 1)
	go m.run(ready)
	if err := <-ready; err != nil {
		return nil, err
	}
	return m, nil
}

// run is the overlay thread: register the class, then serve commands and pump
// messages until quit.
func (m *overlayManager) run(ready chan<- error) {
	runtime.LockOSThread()

	// A NULL instance handle is fine for a private tool-window class in this
	// process. (The binding cannot pass NULL to GetModuleHandle, and we do not
	// need a real module handle for an overlay class.)
	m.hinstance = 0

	cls := wm.WNDCLASSEXW{
		CbSize:        uint32(unsafe.Sizeof(wm.WNDCLASSEXW{})),
		LpfnWndProc:   wm.WNDPROC(wndProcCallback),
		HInstance:     m.hinstance,
		LpszClassName: foundation.PWSTR(win32.UTF16Ptr(overlayClassName)),
	}
	if _, err := wm.RegisterClassEx(&cls); err != nil {
		ready <- err
		return
	}
	ready <- nil

	tick := time.NewTicker(15 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case cmd := <-m.cmds:
			m.handle(cmd)
		case <-tick.C:
		case <-m.quit:
			m.teardown()
			return
		}
		m.pump()
		m.expire()
	}
}

func (m *overlayManager) handle(cmd overlayCmd) {
	switch cmd.kind {
	case cmdHighlight:
		// Replace any existing highlight with the new one.
		if m.highlight != nil {
			m.destroyOverlay(m.highlight)
			m.highlight = nil
		}
		if ov := m.createOverlay(cmd.rect, drawHighlight, highlightTTL); ov != nil {
			m.highlight = ov
		}
	case cmdClick:
		if ov := m.createOverlay(cmd.rect, drawClickRing, clickTTL); ov != nil {
			m.clicks = append(m.clicks, ov)
		}
	case cmdSecurityBanner:
		if m.banner != nil {
			m.destroyOverlay(m.banner)
			m.banner = nil
		}
		if ov := m.createBanner(cmd.text); ov != nil {
			m.banner = ov
		}
	case cmdDismissBanner:
		if m.banner != nil {
			m.destroyOverlay(m.banner)
			m.banner = nil
		}
	}
}

// createBanner draws a persistent, opaque full-width red band with centered
// white text at the top of the primary screen for a security event. GDI text
// leaves glyph pixels with zero alpha, so after drawing the band is forced fully
// opaque — the band is a solid rectangle, so uniform alpha is correct.
func (m *overlayManager) createBanner(text string) *activeOverlay {
	sw := int(wm.GetSystemMetrics(wm.SM_CXSCREEN))
	if sw <= 0 {
		sw = 1280
	}
	rect := Rect{Left: 0, Top: 0, Right: sw, Bottom: bannerHeightPx}
	w, h := rect.Width(), rect.Height()

	hwnd, err := wm.CreateWindowEx(
		overlayExLayeredFlags,
		overlayClassName, "",
		wm.WS_POPUP,
		int32(rect.Left), int32(rect.Top), int32(w), int32(h),
		0, 0, m.hinstance, nil,
	)
	if err != nil || hwnd == 0 {
		m.logger.Warn("overlay: banner CreateWindowEx failed", "error", err)
		return nil
	}
	dc, bitmap, bits, ok := m.makeDIB(w, h)
	if !ok {
		_ = wm.DestroyWindow(hwnd)
		return nil
	}

	// Opaque dark-red background band.
	bg := premul(200, 25, 25, 255)
	for i := range bits {
		bits[i] = bg
	}
	// Centered bold white text via GDI.
	font := gdi.CreateFont(int32(-bannerFontPx), 0, 0, 0, int32(gdi.FW_BOLD), 0, 0, 0,
		uint32(gdi.DEFAULT_CHARSET), 0, 0, 0, 0, "Segoe UI")
	if font != 0 {
		old := gdi.SelectObject(dc, gdi.HGDIOBJ(font))
		gdi.SetBkMode(dc, int32(gdi.TRANSPARENT))
		gdi.SetTextColor(dc, foundation.COLORREF(0x00FFFFFF))
		r := foundation.RECT{Left: 0, Top: 0, Right: int32(w), Bottom: int32(h)}
		gdi.DrawText(dc, foundation.PWSTR(win32.UTF16Ptr(text)), -1, &r,
			gdi.DT_CENTER|gdi.DT_VCENTER|gdi.DT_SINGLELINE)
		gdi.SelectObject(dc, old)
		gdi.DeleteObject(gdi.HGDIOBJ(font))
	}
	// GDI text writes glyph pixels with alpha 0; force the whole band opaque.
	for i := range bits {
		bits[i] |= 0xFF000000
	}

	ptDst := foundation.POINT{X: int32(rect.Left), Y: int32(rect.Top)}
	size := foundation.SIZE{Cx: int32(w), Cy: int32(h)}
	ptSrc := foundation.POINT{X: 0, Y: 0}
	blend := gdi.BLENDFUNCTION{
		BlendOp:             byte(gdi.AC_SRC_OVER),
		SourceConstantAlpha: 255,
		AlphaFormat:         byte(gdi.AC_SRC_ALPHA),
	}
	if err := wm.UpdateLayeredWindow(hwnd, 0, &ptDst, &size, dc, &ptSrc, 0, &blend, wm.ULW_ALPHA); err != nil {
		m.logger.Warn("overlay: banner UpdateLayeredWindow failed", "error", err)
		gdi.DeleteObject(gdi.HGDIOBJ(bitmap))
		gdi.DeleteDC(dc)
		_ = wm.DestroyWindow(hwnd)
		return nil
	}
	wm.ShowWindow(hwnd, wm.SW_SHOWNOACTIVATE)
	return &activeOverlay{hwnd: hwnd, dc: dc, bitmap: bitmap, persistent: true}
}

// showBanner / dismissBanner enqueue security-banner commands.
func (m *overlayManager) showBanner(text string) {
	m.send(overlayCmd{kind: cmdSecurityBanner, text: text})
}
func (m *overlayManager) dismissBanner() {
	m.send(overlayCmd{kind: cmdDismissBanner})
}

// drawFunc fills a premultiplied-BGRA pixel buffer (top-down, width w, height h).
type drawFunc func(px []uint32, w, h int)

// createOverlay builds a layered window covering rect, renders it with draw, and
// shows it. Returns nil (after logging) on any failure.
func (m *overlayManager) createOverlay(rect Rect, draw drawFunc, ttl time.Duration) *activeOverlay {
	w, h := rect.Width(), rect.Height()
	if w <= 0 || h <= 0 {
		return nil
	}

	hwnd, err := wm.CreateWindowEx(
		overlayExLayeredFlags,
		overlayClassName, "",
		wm.WS_POPUP,
		int32(rect.Left), int32(rect.Top), int32(w), int32(h),
		0, 0, m.hinstance, nil,
	)
	if err != nil || hwnd == 0 {
		m.logger.Warn("overlay: CreateWindowEx failed", "error", err)
		return nil
	}

	dc, bitmap, bits, ok := m.makeDIB(w, h)
	if !ok {
		_ = wm.DestroyWindow(hwnd)
		return nil
	}
	draw(bits, w, h)

	ptDst := foundation.POINT{X: int32(rect.Left), Y: int32(rect.Top)}
	size := foundation.SIZE{Cx: int32(w), Cy: int32(h)}
	ptSrc := foundation.POINT{X: 0, Y: 0}
	blend := gdi.BLENDFUNCTION{
		BlendOp:             byte(gdi.AC_SRC_OVER),
		SourceConstantAlpha: 255,
		AlphaFormat:         byte(gdi.AC_SRC_ALPHA),
	}
	if err := wm.UpdateLayeredWindow(hwnd, 0, &ptDst, &size, dc, &ptSrc, 0, &blend, wm.ULW_ALPHA); err != nil {
		m.logger.Warn("overlay: UpdateLayeredWindow failed", "error", err)
		gdi.DeleteObject(gdi.HGDIOBJ(bitmap))
		gdi.DeleteDC(dc)
		_ = wm.DestroyWindow(hwnd)
		return nil
	}
	wm.ShowWindow(hwnd, wm.SW_SHOWNOACTIVATE)

	return &activeOverlay{hwnd: hwnd, dc: dc, bitmap: bitmap, expiry: time.Now().Add(ttl)}
}

// makeDIB creates a 32-bpp top-down DIB section and returns its DC, bitmap, and
// pixel slice (premultiplied BGRA as little-endian 0xAARRGGBB uint32s).
func (m *overlayManager) makeDIB(w, h int) (gdi.HDC, gdi.HBITMAP, []uint32, bool) {
	screenDC := gdi.GetDC(0)
	memDC := gdi.CreateCompatibleDC(screenDC)
	gdi.ReleaseDC(0, screenDC)
	if memDC == 0 {
		return 0, 0, nil, false
	}

	bi := gdi.BITMAPINFO{
		BmiHeader: gdi.BITMAPINFOHEADER{
			BiSize:        uint32(unsafe.Sizeof(gdi.BITMAPINFOHEADER{})),
			BiWidth:       int32(w),
			BiHeight:      -int32(h), // negative => top-down
			BiPlanes:      1,
			BiBitCount:    32,
			BiCompression: 0, // BI_RGB
		},
	}
	var bitsPtr unsafe.Pointer
	bitmap, err := gdi.CreateDIBSection(memDC, &bi, gdi.DIB_RGB_COLORS, &bitsPtr, 0, 0)
	if err != nil || bitmap == 0 || bitsPtr == nil {
		gdi.DeleteDC(memDC)
		return 0, 0, nil, false
	}
	gdi.SelectObject(memDC, gdi.HGDIOBJ(bitmap))
	px := unsafe.Slice((*uint32)(bitsPtr), w*h)
	return memDC, bitmap, px, true
}

func (m *overlayManager) pump() {
	var msg wm.MSG
	for wm.PeekMessage(&msg, 0, 0, 0, wm.PM_REMOVE) {
		wm.TranslateMessage(&msg)
		wm.DispatchMessage(&msg)
	}
}

func (m *overlayManager) expire() {
	now := time.Now()
	if m.highlight != nil && now.After(m.highlight.expiry) {
		m.destroyOverlay(m.highlight)
		m.highlight = nil
	}
	if len(m.clicks) == 0 {
		return
	}
	kept := m.clicks[:0]
	for _, ov := range m.clicks {
		if now.After(ov.expiry) {
			m.destroyOverlay(ov)
		} else {
			kept = append(kept, ov)
		}
	}
	m.clicks = kept
}

func (m *overlayManager) destroyOverlay(ov *activeOverlay) {
	if ov == nil {
		return
	}
	if ov.bitmap != 0 {
		gdi.DeleteObject(gdi.HGDIOBJ(ov.bitmap))
	}
	if ov.dc != 0 {
		gdi.DeleteDC(ov.dc)
	}
	if ov.hwnd != 0 {
		_ = wm.DestroyWindow(ov.hwnd)
	}
}

func (m *overlayManager) teardown() {
	if m.highlight != nil {
		m.destroyOverlay(m.highlight)
		m.highlight = nil
	}
	for _, ov := range m.clicks {
		m.destroyOverlay(ov)
	}
	m.clicks = nil
	if m.banner != nil {
		m.destroyOverlay(m.banner)
		m.banner = nil
	}
	wm.UnregisterClass(overlayClassName, m.hinstance)
}

// flashClick enqueues an orange ring centered at (x,y).
func (m *overlayManager) flashClick(x, y int) {
	r := clickRadiusPx
	rect := Rect{Left: x - r, Top: y - r, Right: x + r, Bottom: y + r}
	m.send(overlayCmd{kind: cmdClick, rect: rect})
}

// highlightWindow enqueues a green border around rect.
func (m *overlayManager) highlightWindow(rect Rect) {
	if rect.Empty() {
		return
	}
	m.send(overlayCmd{kind: cmdHighlight, rect: rect})
}

func (m *overlayManager) send(cmd overlayCmd) {
	select {
	case m.cmds <- cmd:
	case <-m.quit:
	default:
		// Drop if the queue is full: overlays are best-effort decoration.
	}
}

func (m *overlayManager) close() {
	select {
	case <-m.quit:
	default:
		close(m.quit)
	}
}

// premul returns a premultiplied-alpha BGRA pixel as a little-endian uint32
// (0xAARRGGBB in memory order B,G,R,A).
func premul(r, g, b, a uint32) uint32 {
	pr := r * a / 255
	pg := g * a / 255
	pb := b * a / 255
	return (a << 24) | (pr << 16) | (pg << 8) | pb
}

// drawHighlight fills a hollow green border of highlightBorderPx thickness.
func drawHighlight(px []uint32, w, h int) {
	green := premul(40, 210, 70, highlightAlpha)
	t := highlightBorderPx
	for y := range h {
		edgeRow := y < t || y >= h-t
		for x := range w {
			if edgeRow || x < t || x >= w-t {
				px[y*w+x] = green
			}
		}
	}
}

// drawClickRing fills an orange annulus (ring) centered in the buffer.
func drawClickRing(px []uint32, w, h int) {
	orange := premul(255, 140, 0, clickAlpha)
	cx, cy := float64(w)/2, float64(h)/2
	outer := float64(clickRadiusPx)
	inner := outer - float64(clickRingThicknessPx)
	outer2, inner2 := outer*outer, inner*inner
	for y := range h {
		dy := float64(y) - cy
		for x := range w {
			dx := float64(x) - cx
			d2 := dx*dx + dy*dy
			if d2 <= outer2 && d2 >= inner2 {
				px[y*w+x] = orange
			}
		}
	}
}
