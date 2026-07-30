//go:build windows && (amd64 || arm64)

package desktop

import (
	"fmt"
	"image"
	"unsafe"

	gdi "github.com/deploymenttheory/go-bindings-win32/bindings/win32/graphics/gdi"
	wm "github.com/deploymenttheory/go-bindings-win32/bindings/win32/ui/windowsandmessaging"
)

// captureScreen grabs the entire virtual desktop (all monitors) into an RGBA
// image, downscaling by an integer factor when wider than maxWidth. It uses a
// self-contained GDI pipeline (its own DCs) and does not require the engine STA
// thread, so it is safe to call from the recorder goroutine as well as from
// Screenshot. Returns the image, its dimensions, and the downscale denominator
// (1 = none).
func captureScreen(maxWidth int) (img *image.RGBA, ew, eh, denom int, err error) {
	// The virtual-screen metrics are kept in the int32 GetSystemMetrics returns
	// and handed to GDI unchanged. Widening them to int and narrowing back for
	// every call was a round-trip that could not lose information but did have to
	// be justified at nine separate conversions.
	vx := wm.GetSystemMetrics(wm.SM_XVIRTUALSCREEN)
	vy := wm.GetSystemMetrics(wm.SM_YVIRTUALSCREEN)
	vw := wm.GetSystemMetrics(wm.SM_CXVIRTUALSCREEN)
	vh := wm.GetSystemMetrics(wm.SM_CYVIRTUALSCREEN)
	if vw <= 0 || vh <= 0 {
		return nil, 0, 0, 0, fmt.Errorf("invalid virtual screen size %dx%d", vw, vh)
	}
	// Widening for the pixel arithmetic below is always lossless.
	width, height := int(vw), int(vh)

	screenDC := gdi.GetDC(0)
	if screenDC == 0 {
		return nil, 0, 0, 0, fmt.Errorf("GetDC(screen) failed")
	}
	defer gdi.ReleaseDC(0, screenDC)

	memDC := gdi.CreateCompatibleDC(screenDC)
	if memDC == 0 {
		return nil, 0, 0, 0, fmt.Errorf("CreateCompatibleDC failed")
	}
	defer gdi.DeleteDC(memDC)

	bitmap := gdi.CreateCompatibleBitmap(screenDC, vw, vh)
	if bitmap == 0 {
		return nil, 0, 0, 0, fmt.Errorf("CreateCompatibleBitmap failed")
	}
	defer gdi.DeleteObject(gdi.HGDIOBJ(bitmap))
	gdi.SelectObject(memDC, gdi.HGDIOBJ(bitmap))

	if err := gdi.BitBlt(memDC, 0, 0, vw, vh, screenDC, vx, vy, gdi.SRCCOPY); err != nil {
		return nil, 0, 0, 0, fmt.Errorf("BitBlt: %w", err)
	}

	buf := make([]byte, width*height*4)
	bi := gdi.BITMAPINFO{
		BmiHeader: gdi.BITMAPINFOHEADER{
			BiSize:        uint32(unsafe.Sizeof(gdi.BITMAPINFOHEADER{})),
			BiWidth:       vw,
			BiHeight:      -vh, // top-down
			BiPlanes:      1,
			BiBitCount:    32,
			BiCompression: 0, // BI_RGB
		},
	}
	if got := gdi.GetDIBits(memDC, bitmap, 0, uint32(vh), unsafe.Pointer(&buf[0]), &bi, gdi.DIB_RGB_COLORS); got == 0 {
		return nil, 0, 0, 0, fmt.Errorf("GetDIBits returned 0 scanlines")
	}

	img, ew, eh, denom = bgraToRGBA(buf, width, height, maxWidth)
	return img, ew, eh, denom, nil
}

// bgraToRGBA converts a top-down BGRA buffer to an RGBA image, downscaling by an
// integer factor (nearest-neighbor) when wider than maxWidth (<=0 disables the
// cap). Returns the image, its dimensions, and the downscale denominator.
func bgraToRGBA(buf []byte, w, h, maxWidth int) (*image.RGBA, int, int, int) {
	factor := 1
	if maxWidth > 0 {
		for w/factor > maxWidth {
			factor++
		}
	}
	ew, eh := w/factor, h/factor
	img := image.NewRGBA(image.Rect(0, 0, ew, eh))
	for y := range eh {
		sy := y * factor
		for x := range ew {
			sx := x * factor
			i := (sy*w + sx) * 4
			b, g, r := buf[i], buf[i+1], buf[i+2]
			o := img.PixOffset(x, y)
			img.Pix[o] = r
			img.Pix[o+1] = g
			img.Pix[o+2] = b
			img.Pix[o+3] = 255
		}
	}
	return img, ew, eh, factor
}
