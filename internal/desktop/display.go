//go:build windows && (amd64 || arm64)

package desktop

import (
	"syscall"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	gdi "github.com/deploymenttheory/go-bindings-win32/bindings/win32/graphics/gdi"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/ui/hidpi"
)

// monitorInfoFlagPrimary is MONITORINFOF_PRIMARY.
const monitorInfoFlagPrimary = 1

// mdtEffectiveDPI is MDT_EFFECTIVE_DPI for GetDpiForMonitor.
const mdtEffectiveDPI = hidpi.MONITOR_DPI_TYPE(0)

// DisplayInfo describes one monitor.
type DisplayInfo struct {
	Index    int
	Primary  bool
	Bounds   Rect // full monitor rectangle (virtual-screen coords)
	WorkArea Rect // usable area excluding taskbar
	DPI      int  // effective DPI (96 = 100%)
	ScalePct int  // scale percentage (e.g. 150)
}

// enumMonitorsSink collects HMONITOR handles for the shared callback. Only
// touched on the engine STA thread.
var enumMonitorsSink *[]gdi.HMONITOR

var enumMonitorsCallback = syscall.NewCallback(func(hmon uintptr, _ uintptr, _ uintptr, _ uintptr) uintptr {
	if enumMonitorsSink != nil {
		*enumMonitorsSink = append(*enumMonitorsSink, gdi.HMONITOR(hmon))
	}
	return 1 // continue
})

func rectFrom(r foundation.RECT) Rect {
	return Rect{Left: int(r.Left), Top: int(r.Top), Right: int(r.Right), Bottom: int(r.Bottom)}
}

// Displays enumerates the monitors with their bounds, work area, and DPI/scale.
func (d *Desktop) Displays() ([]DisplayInfo, error) {
	var displays []DisplayInfo
	err := d.Do(func() error {
		var handles []gdi.HMONITOR
		enumMonitorsSink = &handles
		gdi.EnumDisplayMonitors(0, nil, gdi.MONITORENUMPROC(enumMonitorsCallback), 0)
		enumMonitorsSink = nil

		for i, h := range handles {
			mi := gdi.MONITORINFO{CbSize: uint32(unsafe.Sizeof(gdi.MONITORINFO{}))}
			if !gdi.GetMonitorInfo(h, &mi) {
				continue
			}
			info := DisplayInfo{
				Index:    i,
				Primary:  mi.DwFlags&monitorInfoFlagPrimary != 0,
				Bounds:   rectFrom(mi.RcMonitor),
				WorkArea: rectFrom(mi.RcWork),
				DPI:      96,
				ScalePct: 100,
			}
			var dpiX, dpiY uint32
			if err := hidpi.GetDpiForMonitor(h, mdtEffectiveDPI, &dpiX, &dpiY); err == nil && dpiX > 0 {
				info.DPI = int(dpiX)
				info.ScalePct = int(dpiX) * 100 / 96
			}
			displays = append(displays, info)
		}
		return nil
	})
	return displays, err
}
