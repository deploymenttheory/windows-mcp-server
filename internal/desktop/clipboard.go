//go:build windows && (amd64 || arm64)

package desktop

import (
	"fmt"
	"unicode/utf16"
	"unsafe"

	win32 "github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/dataexchange"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/memory"
)

// cfUnicodeText is the CF_UNICODETEXT clipboard format (UTF-16 text).
const cfUnicodeText = 13

// gmemMoveable is the GMEM_MOVEABLE global-allocation flag required for
// clipboard memory.
const gmemMoveable = memory.GMEM_MOVEABLE

// ClipboardGet returns the clipboard's Unicode text, or "" if the clipboard
// holds no text. It runs on the engine STA thread.
func (d *Desktop) ClipboardGet() (string, error) {
	var text string
	err := d.Do(func() error {
		if e := dataexchange.OpenClipboard(0); e != nil {
			return fmt.Errorf("OpenClipboard: %w", e)
		}
		defer func() { _ = dataexchange.CloseClipboard() }()

		if e := dataexchange.IsClipboardFormatAvailable(cfUnicodeText); e != nil {
			// No unicode text on the clipboard: return empty, not an error.
			return nil
		}
		h, e := dataexchange.GetClipboardData(cfUnicodeText)
		if e != nil {
			return fmt.Errorf("GetClipboardData: %w", e)
		}
		if h == 0 {
			return nil
		}
		ptr, e := memory.GlobalLock(foundation.HGLOBAL(h))
		if e != nil {
			return fmt.Errorf("GlobalLock: %w", e)
		}
		defer func() { _ = memory.GlobalUnlock(foundation.HGLOBAL(h)) }()

		text = win32.UTF16ToString((*uint16)(ptr))
		return nil
	})
	return text, err
}

// ClipboardSet replaces the clipboard contents with the given Unicode text. It
// runs on the engine STA thread.
func (d *Desktop) ClipboardSet(text string) error {
	return d.Do(func() error {
		if e := dataexchange.OpenClipboard(0); e != nil {
			return fmt.Errorf("OpenClipboard: %w", e)
		}
		defer func() { _ = dataexchange.CloseClipboard() }()

		if e := dataexchange.EmptyClipboard(); e != nil {
			return fmt.Errorf("EmptyClipboard: %w", e)
		}

		// Encode as null-terminated UTF-16.
		units := utf16.Encode([]rune(text))
		units = append(units, 0)
		byteLen := uintptr(len(units)) * unsafe.Sizeof(uint16(0))

		hMem, e := memory.GlobalAlloc(gmemMoveable, byteLen)
		if e != nil {
			return fmt.Errorf("GlobalAlloc: %w", e)
		}

		ptr, e := memory.GlobalLock(hMem)
		if e != nil {
			return fmt.Errorf("GlobalLock: %w", e)
		}
		dst := unsafe.Slice((*uint16)(ptr), len(units))
		copy(dst, units)
		_ = memory.GlobalUnlock(hMem)

		// Ownership of hMem transfers to the system on success.
		if _, e := dataexchange.SetClipboardData(cfUnicodeText, foundation.HANDLE(hMem)); e != nil {
			return fmt.Errorf("SetClipboardData: %w", e)
		}
		return nil
	})
}
