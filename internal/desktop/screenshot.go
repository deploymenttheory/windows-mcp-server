//go:build windows && (amd64 || arm64)

package desktop

import (
	"bytes"
	"fmt"
	"image/png"
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
		img, ew, eh, denom, e := captureScreen(maxScreenshotWidth)
		if e != nil {
			return e
		}
		var out bytes.Buffer
		if e := png.Encode(&out, img); e != nil {
			return fmt.Errorf("png encode: %w", e)
		}
		pngData = out.Bytes()
		width, height, scaleDenom = ew, eh, denom
		return nil
	})
	return pngData, width, height, scaleDenom, err
}
