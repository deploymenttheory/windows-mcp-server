//go:build windows && (amd64 || arm64)

package desktop

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	km "github.com/deploymenttheory/go-bindings-win32/bindings/win32/ui/input/keyboardandmouse"
	wm "github.com/deploymenttheory/go-bindings-win32/bindings/win32/ui/windowsandmessaging"
)

// inputSize is the size of one INPUT record, passed to SendInput.
var inputSize = int32(unsafe.Sizeof(km.INPUT{}))

// ErrCoordinateOutOfRange reports a coordinate that cannot be represented in the
// display coordinate space.
var ErrCoordinateOutOfRange = errors.New("coordinate is outside the display coordinate space")

// screenCoord narrows a caller-supplied coordinate to the int32 the Win32 input
// APIs take, rejecting values that do not fit instead of silently wrapping.
//
// These coordinates arrive from tool arguments — i.e. from the agent — and are
// not otherwise range-checked. A bare int32(v) on a 64-bit build wraps:
// int32(1<<32 + 100) is 100, so an absurd coordinate would quietly act on a real
// point on screen rather than failing. Negative values are deliberately allowed:
// a multi-monitor virtual desktop legitimately has a negative origin.
func screenCoord(v int, name string) (int32, error) {
	if v < math.MinInt32 || v > math.MaxInt32 {
		return 0, fmt.Errorf("%w: %s %d", ErrCoordinateOutOfRange, name, v)
	}
	return int32(v), nil
}

// screenPoint validates an (x, y) pair.
func screenPoint(x, y int) (ix, iy int32, err error) {
	if ix, err = screenCoord(x, "x coordinate"); err != nil {
		return 0, 0, err
	}
	if iy, err = screenCoord(y, "y coordinate"); err != nil {
		return 0, 0, err
	}
	return ix, iy, nil
}

// setCursor validates a point and moves the cursor to it.
func setCursor(x, y int) error {
	ix, iy, err := screenPoint(x, y)
	if err != nil {
		return err
	}
	if err := wm.SetCursorPos(ix, iy); err != nil {
		return fmt.Errorf("SetCursorPos: %w", err)
	}
	return nil
}

// sendInputs injects a batch of synthesized input events.
func sendInputs(inputs []km.INPUT) error {
	if len(inputs) == 0 {
		return nil
	}
	n, err := km.SendInput(inputs, inputSize)
	if err != nil {
		return fmt.Errorf("SendInput: %w", err)
	}
	if int(n) != len(inputs) {
		return fmt.Errorf("SendInput injected %d of %d events", n, len(inputs))
	}
	return nil
}

// mouseInput builds a mouse INPUT with the given flags and data, writing the
// MOUSEINPUT into the INPUT union's backing bytes.
func mouseInput(flags km.MOUSE_EVENT_FLAGS, data uint32) km.INPUT {
	in := km.INPUT{Type: km.INPUT_MOUSE}
	mi := (*km.MOUSEINPUT)(unsafe.Pointer(&in.Anonymous))
	mi.DwFlags = flags
	mi.MouseData = data
	return in
}

// unicodeKeyInput builds a keyboard INPUT that emits a UTF-16 code unit,
// bypassing keyboard-layout/VK mapping (works for arbitrary text).
func unicodeKeyInput(unit uint16, keyUp bool) km.INPUT {
	in := km.INPUT{Type: km.INPUT_KEYBOARD}
	ki := (*km.KEYBDINPUT)(unsafe.Pointer(&in.Anonymous))
	ki.WScan = unit
	ki.DwFlags = km.KEYEVENTF_UNICODE
	if keyUp {
		ki.DwFlags |= km.KEYEVENTF_KEYUP
	}
	return in
}

// vkeyInput builds a keyboard INPUT for a virtual key.
func vkeyInput(vk km.VIRTUAL_KEY, keyUp bool) km.INPUT {
	in := km.INPUT{Type: km.INPUT_KEYBOARD}
	ki := (*km.KEYBDINPUT)(unsafe.Pointer(&in.Anonymous))
	ki.WVk = vk
	if keyUp {
		ki.DwFlags = km.KEYEVENTF_KEYUP
	}
	return in
}

// Click moves the cursor to (x,y) and clicks. button is "left", "right", or
// "middle"; clicks of 0 hovers (move only), 1 single-clicks, 2 double-clicks.
func (d *Desktop) Click(x, y int, button string, clicks int) error {
	if d.overlay != nil && clicks > 0 {
		d.overlay.flashClick(x, y)
	}
	return d.Do(func() error {
		if err := setCursor(x, y); err != nil {
			return err
		}
		if clicks <= 0 {
			return nil // hover only
		}
		time.Sleep(10 * time.Millisecond)

		var down, up km.MOUSE_EVENT_FLAGS
		switch button {
		case "right":
			down, up = km.MOUSEEVENTF_RIGHTDOWN, km.MOUSEEVENTF_RIGHTUP
		case "middle":
			down, up = km.MOUSEEVENTF_MIDDLEDOWN, km.MOUSEEVENTF_MIDDLEUP
		default:
			down, up = km.MOUSEEVENTF_LEFTDOWN, km.MOUSEEVENTF_LEFTUP
		}
		for i := range clicks {
			if err := sendInputs([]km.INPUT{mouseInput(down, 0), mouseInput(up, 0)}); err != nil {
				return err
			}
			if i < clicks-1 {
				time.Sleep(60 * time.Millisecond)
			}
		}
		return nil
	})
}

// leftClickAt performs one left click at (x,y).
//
// STA-only: it must be called from inside a Do job. Click cannot be reused from
// within another Do job because Click wraps itself in Do, and the job channel is
// unbuffered — re-entering would deadlock the engine thread.
func leftClickAt(x, y int) error {
	if err := setCursor(x, y); err != nil {
		return err
	}
	time.Sleep(10 * time.Millisecond) // let the target window register the move
	return sendInputs([]km.INPUT{
		mouseInput(km.MOUSEEVENTF_LEFTDOWN, 0),
		mouseInput(km.MOUSEEVENTF_LEFTUP, 0),
	})
}

// ClickMany left-clicks a series of points in order. When holdCtrl is true,
// Ctrl is held down for the whole sequence (multi-select).
func (d *Desktop) ClickMany(points [][2]int, holdCtrl bool) error {
	if len(points) == 0 {
		return nil
	}
	if d.overlay != nil {
		for _, p := range points {
			d.overlay.flashClick(p[0], p[1])
		}
	}
	return d.Do(func() error {
		if holdCtrl {
			if err := sendInputs([]km.INPUT{vkeyInput(km.VK_CONTROL, false)}); err != nil {
				return err
			}
			defer func() { _ = sendInputs([]km.INPUT{vkeyInput(km.VK_CONTROL, true)}) }()
		}
		for i, p := range points {
			if err := setCursor(p[0], p[1]); err != nil {
				return err
			}
			time.Sleep(10 * time.Millisecond)
			if err := sendInputs([]km.INPUT{
				mouseInput(km.MOUSEEVENTF_LEFTDOWN, 0),
				mouseInput(km.MOUSEEVENTF_LEFTUP, 0),
			}); err != nil {
				return err
			}
			if i < len(points)-1 {
				time.Sleep(80 * time.Millisecond)
			}
		}
		return nil
	})
}

// MoveCursor moves the cursor to (x,y) without clicking.
func (d *Desktop) MoveCursor(x, y int) error {
	return d.Do(func() error {
		if err := setCursor(x, y); err != nil {
			return err
		}
		return nil
	})
}

// TypeText types Unicode text at the current focus. Newlines and tabs are sent
// as Enter and Tab virtual keys; all other characters are sent as Unicode
// keystrokes so no keyboard-layout mapping is needed.
func (d *Desktop) TypeText(text string) error {
	return d.Do(func() error {
		for _, r := range text {
			switch r {
			case '\n':
				if err := sendInputs(
					[]km.INPUT{vkeyInput(km.VK_RETURN, false), vkeyInput(km.VK_RETURN, true)},
				); err != nil {
					return err
				}
			case '\t':
				if err := sendInputs(
					[]km.INPUT{vkeyInput(km.VK_TAB, false), vkeyInput(km.VK_TAB, true)},
				); err != nil {
					return err
				}
			case '\r':
				// ignore; handled by \n
			default:
				for _, u := range utf16.Encode([]rune{r}) {
					if err := sendInputs(
						[]km.INPUT{unicodeKeyInput(u, false), unicodeKeyInput(u, true)},
					); err != nil {
						return err
					}
				}
			}
			time.Sleep(3 * time.Millisecond)
		}
		return nil
	})
}

// maxWheelClicks bounds a single Scroll call.
//
// wheelClicks arrives from a tool argument, so it is agent-supplied, and the
// scroll loop sleeps 10ms per notch on the engine's one serialized STA thread.
// Unbounded, a single call could hold that thread — and every automation call
// queued behind it — for as long as the agent asked: 20 million clicks is over
// 50 hours. A thousand notches is already far past any real scroll.
const maxWheelClicks = 1000

// boundWheelClicks clamps the requested notch count into the usable range.
func boundWheelClicks(n int) int {
	switch {
	case n < 1:
		return 1
	case n > maxWheelClicks:
		return maxWheelClicks
	default:
		return n
	}
}

// scrollDirection maps a direction name to the wheel sign and whether the
// scroll is horizontal (emulated by holding Shift over the vertical wheel).
// An unrecognized direction scrolls down, matching the Python implementation.
//
// The sign used to be derived from wheelDelta*int32(wheelClicks) and read off
// that product's sign, which inverted the scroll once it exceeded int32:
// 120 * 20_000_000 wraps negative, so "up" scrolled down. The magnitude was
// never used for anything else — the loop emits one notch per click — so the
// direction is now decided on its own.
func scrollDirection(direction string) (down, horizontal bool) {
	switch direction {
	case "up":
		return false, false
	case "right":
		return false, true
	case "left":
		return true, true
	default: // "down" and anything unrecognized
		return true, false
	}
}

// Scroll moves the cursor to (x,y) and scrolls the wheel. direction is "up",
// "down", "left", or "right"; wheelClicks is the number of wheel notches.
// Horizontal scrolling is emulated by holding Shift over the vertical wheel,
// matching the Python implementation.
func (d *Desktop) Scroll(x, y, wheelClicks int, direction string) error {
	wheelClicks = boundWheelClicks(wheelClicks)
	return d.Do(func() error {
		if err := setCursor(x, y); err != nil {
			return err
		}
		const wheelDelta = 120
		down, horizontal := scrollDirection(direction)

		if horizontal {
			if err := sendInputs([]km.INPUT{vkeyInput(km.VK_SHIFT, false)}); err != nil {
				return err
			}
			defer func() { _ = sendInputs([]km.INPUT{vkeyInput(km.VK_SHIFT, true)}) }()
		}
		for range wheelClicks {
			unit := int32(wheelDelta)
			if down {
				unit = -wheelDelta
			}
			// The wheel delta is a *signed* value carried in an unsigned mouseData
			// field: scrolling down is -120, which Windows expects as the
			// two's-complement bit pattern 0xFFFFFF88. The conversion is a
			// deliberate reinterpretation, not a range error.
			//
			// Kept as its own short statement so the formatter cannot split the
			// call across lines and strand the nolint on a line that no longer
			// holds the conversion — which is exactly what happened before.
			wheelData := uint32(unit) //nolint:gosec // deliberate, see above
			if err := sendInputs(
				[]km.INPUT{mouseInput(km.MOUSEEVENTF_WHEEL, wheelData)},
			); err != nil {
				return err
			}
			time.Sleep(10 * time.Millisecond)
		}
		return nil
	})
}

// SendShortcut presses a key chord, e.g. []string{"ctrl","shift","esc"}. Keys
// are pressed in order and released in reverse.
func (d *Desktop) SendShortcut(keys []string) error {
	vks := make([]km.VIRTUAL_KEY, 0, len(keys))
	for _, k := range keys {
		vk, ok := keyNameToVK(k)
		if !ok {
			return fmt.Errorf("unknown key %q", k)
		}
		vks = append(vks, vk)
	}
	if len(vks) == 0 {
		return fmt.Errorf("no keys given")
	}
	return d.Do(func() error {
		inputs := make([]km.INPUT, 0, len(vks)*2)
		for _, vk := range vks {
			inputs = append(inputs, vkeyInput(vk, false))
		}
		for i := len(vks) - 1; i >= 0; i-- {
			inputs = append(inputs, vkeyInput(vks[i], true))
		}
		return sendInputs(inputs)
	})
}

// namedKeys maps key names to virtual-key codes.
var namedKeys = map[string]km.VIRTUAL_KEY{
	"ctrl": km.VK_CONTROL, "control": km.VK_CONTROL,
	"alt": km.VK_MENU, "option": km.VK_MENU,
	"shift":     km.VK_SHIFT,
	"win":       km.VK_LWIN,
	"windows":   km.VK_LWIN,
	"super":     km.VK_LWIN,
	"cmd":       km.VK_LWIN,
	"meta":      km.VK_LWIN,
	"enter":     km.VK_RETURN,
	"return":    km.VK_RETURN,
	"tab":       km.VK_TAB,
	"esc":       km.VK_ESCAPE,
	"escape":    km.VK_ESCAPE,
	"space":     km.VK_SPACE,
	"backspace": km.VK_BACK,
	"back":      km.VK_BACK,
	"delete":    km.VK_DELETE,
	"del":       km.VK_DELETE,
	"home":      km.VK_HOME,
	"end":       km.VK_END,
	"up":        km.VK_UP,
	"down":      km.VK_DOWN,
	"left":      km.VK_LEFT,
	"right":     km.VK_RIGHT,
}

// keyNameToVK resolves a key name to a virtual-key code. Single letters and
// digits map to their VK directly; longer names use the namedKeys table.
func keyNameToVK(name string) (km.VIRTUAL_KEY, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	if vk, ok := namedKeys[n]; ok {
		return vk, true
	}
	if len(n) == 1 {
		c := n[0]
		switch {
		case c >= 'a' && c <= 'z':
			return km.VIRTUAL_KEY(c - 'a' + 'A'), true // VK_A..VK_Z == 'A'..'Z'
		case c >= '0' && c <= '9':
			return km.VIRTUAL_KEY(c), true // VK_0..VK_9 == '0'..'9'
		}
	}
	return 0, false
}
