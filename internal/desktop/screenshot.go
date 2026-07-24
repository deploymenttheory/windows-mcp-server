//go:build windows && (amd64 || arm64)

package desktop

import (
	"bytes"
	"fmt"
	"image"
	"image/png"
	"unsafe"

	gdi "github.com/deploymenttheory/go-bindings-win32/bindings/win32/graphics/gdi"
	wm "github.com/deploymenttheory/go-bindings-win32/bindings/win32/ui/windowsandmessaging"
)

// maxScreenshotWidth bounds the encoded image width; larger captures are
// downscaled by an integer factor so the PNG stays a reasonable size.
const maxScreenshotWidth = 1920

// Screenshot captures the entire virtual desktop (all monitors) as a PNG.
// Returns the PNG bytes and the encoded image dimensions. Coordinates from
// Snapshot are in physical pixels; if the returned image was downscaled, its
// dimensions differ from the physical desktop (the caller reports the scale).
func (d *Desktop) Screenshot() (pngData []byte, width, height int, scaleDenom int, err error) {
	err = d.Do(func() error {
		vx := int(wm.GetSystemMetrics(wm.SM_XVIRTUALSCREEN))
		vy := int(wm.GetSystemMetrics(wm.SM_YVIRTUALSCREEN))
		vw := int(wm.GetSystemMetrics(wm.SM_CXVIRTUALSCREEN))
		vh := int(wm.GetSystemMetrics(wm.SM_CYVIRTUALSCREEN))
		if vw <= 0 || vh <= 0 {
			return fmt.Errorf("invalid virtual screen size %dx%d", vw, vh)
		}

		screenDC := gdi.GetDC(0)
		if screenDC == 0 {
			return fmt.Errorf("GetDC(screen) failed")
		}
		defer gdi.ReleaseDC(0, screenDC)

		memDC := gdi.CreateCompatibleDC(screenDC)
		if memDC == 0 {
			return fmt.Errorf("CreateCompatibleDC failed")
		}
		defer gdi.DeleteDC(memDC)

		bitmap := gdi.CreateCompatibleBitmap(screenDC, int32(vw), int32(vh))
		if bitmap == 0 {
			return fmt.Errorf("CreateCompatibleBitmap failed")
		}
		defer gdi.DeleteObject(gdi.HGDIOBJ(bitmap))
		gdi.SelectObject(memDC, gdi.HGDIOBJ(bitmap))

		if err := gdi.BitBlt(memDC, 0, 0, int32(vw), int32(vh), screenDC, int32(vx), int32(vy), gdi.SRCCOPY); err != nil {
			return fmt.Errorf("BitBlt: %w", err)
		}

		// Extract pixels as top-down 32-bpp BGRA.
		buf := make([]byte, vw*vh*4)
		bi := gdi.BITMAPINFO{
			BmiHeader: gdi.BITMAPINFOHEADER{
				BiSize:        uint32(unsafe.Sizeof(gdi.BITMAPINFOHEADER{})),
				BiWidth:       int32(vw),
				BiHeight:      -int32(vh), // top-down
				BiPlanes:      1,
				BiBitCount:    32,
				BiCompression: 0, // BI_RGB
			},
		}
		if got := gdi.GetDIBits(memDC, bitmap, 0, uint32(vh), unsafe.Pointer(&buf[0]), &bi, gdi.DIB_RGB_COLORS); got == 0 {
			return fmt.Errorf("GetDIBits returned 0 scanlines")
		}

		img, ew, eh, denom := bgraToImage(buf, vw, vh)
		var out bytes.Buffer
		if err := png.Encode(&out, img); err != nil {
			return fmt.Errorf("png encode: %w", err)
		}
		pngData = out.Bytes()
		width, height, scaleDenom = ew, eh, denom
		return nil
	})
	return pngData, width, height, scaleDenom, err
}

// bgraToimage converts a top-down BGRA buffer to an RGBA image, downscaling by
// an integer factor (nearest-neighbor) when wider than maxScreenshotWidth. It
// returns the image, its dimensions, and the downscale denominator (1 = none).
func bgraToImage(buf []byte, w, h int) (*image.RGBA, int, int, int) {
	factor := 1
	for w/factor > maxScreenshotWidth {
		factor++
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
