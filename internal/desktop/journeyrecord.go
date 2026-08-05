//go:build windows && (amd64 || arm64)

package desktop

import (
	"context"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/ui/accessibility"
	wm "github.com/deploymenttheory/go-bindings-win32/bindings/win32/ui/windowsandmessaging"
)

// This file is the enrichment half of the journey recorder. It consumes the raw,
// COM-free events the hook thread produces (journeyhook_windows.go) and turns each
// into a RecordedInput: a click is resolved to the UI element under it, and a
// keystroke is translated to a character (with the field's password state) or a
// named key. All UIA work happens on the engine STA thread via Do; the hook thread
// never touches COM.

// DefaultRecordStopKey is the virtual-key code that ends a recording (F9), and
// DefaultRecordMarkKey the one that marks an assertion (F8). Both are consumed,
// not recorded, so pressing either never appears in the journey.
const (
	DefaultRecordStopKey = 0x78 // VK_F9
	DefaultRecordMarkKey = 0x77 // VK_F8
)

// doubleClickWindowMS and doubleClickSlopPx are the thresholds for merging two
// clicks into a double-click.
const (
	doubleClickWindowMS = 500
	doubleClickSlopPx   = 5
)

// RecordedInput is one enriched user action the recorder emits. It is engine-level
// and holds no journey types; the caller maps it to a journey event.
type RecordedInput struct {
	Kind    string      // "click" | "char" | "key" | "assert"
	X, Y    int         // click point, or the cursor position at a mark
	Element ElementInfo // the element under a click or mark (resolved via UIA)
	// State is what that element can do and what it currently holds. It is read at
	// the same hit-test, which is the only moment both the element and its tree are
	// in hand — and it is what lets a click be recorded as the verb it meant rather
	// than as a click.
	State  ElementState
	Button string // left | right | middle
	Double bool   // a double-click
	Char   rune   // a typed character
	Secure bool   // the char was typed into a password field → redact
	Key    string // a named non-text key (Enter, Tab, …)
}

// RecordInput installs input hooks and streams enriched events to out until ctx is
// cancelled or the stop key is pressed. It runs the caller's out on the recorder
// goroutine; out must not block for long.
//
// It reads live UI state and only works on an interactive desktop; on a host that
// cannot host UIA the hit-test simply yields empty element info and clicks fall
// back to coordinates.
func (d *Desktop) RecordInput(ctx context.Context, stopVK uint32, out func(RecordedInput)) error {
	return d.RecordInputWithMark(ctx, stopVK, DefaultRecordMarkKey, out)
}

// RecordInputWithMark is RecordInput with an explicit assertion-mark key.
//
// The mark key is what turns a recording into a test. A capture of a human doing
// a task records the actions and notices nothing about whether they worked;
// pointing at what matters and pressing the key is the cheapest moment to say so,
// because it is the moment the author is already looking at it.
func (d *Desktop) RecordInputWithMark(
	ctx context.Context,
	stopVK, markVK uint32,
	out func(RecordedInput),
) error {
	hooks, err := startInputHooks()
	if err != nil {
		return err
	}
	defer hooks.stop()

	var lastMS uint32
	var lastX, lastY int

	for {
		select {
		case <-ctx.Done():
			return nil
		case in := <-hooks.events:
			switch in.kind {
			case rawMouseDown:
				info, state := d.inspectPoint(in.x, in.y)
				double := in.timeMS-lastMS <= doubleClickWindowMS &&
					absInt(in.x-lastX) <= doubleClickSlopPx && absInt(in.y-lastY) <= doubleClickSlopPx
				lastMS, lastX, lastY = in.timeMS, in.x, in.y
				out(RecordedInput{
					Kind: "click", X: in.x, Y: in.y,
					Element: info, State: state, Button: in.button, Double: double,
				})
			case rawKeyDown:
				if stopVK != 0 && in.vk == stopVK {
					return nil
				}
				if markVK != 0 && in.vk == markVK {
					// Marked where the pointer is, not where focus is: the author is
					// pointing at the thing they mean, which is rarely the focused control.
					x, y := cursorPoint()
					info, state := d.inspectPoint(x, y)
					out(RecordedInput{Kind: "assert", X: x, Y: y, Element: info, State: state})
					continue
				}
				if r, printable, key := translateKey(in.vk, in.shift, in.caps); printable {
					// Fail closed: a keystroke whose destination cannot be
					// established is treated as secret. See focusedIsPassword.
					secure := true
					_ = d.Do(func() error {
						secure = d.focusedIsPassword()
						return nil
					})
					out(RecordedInput{Kind: "char", Char: r, Secure: secure})
				} else if key != "" {
					out(RecordedInput{Kind: "key", Key: key})
				}
			}
		}
	}
}

// inspectPoint resolves the element under a point and reads its state, both on
// the STA thread and both from the same element.
func (d *Desktop) inspectPoint(x, y int) (ElementInfo, ElementState) {
	var (
		info  ElementInfo
		state ElementState
	)
	_ = d.Do(func() error {
		info, state = d.elementAtPoint(x, y)
		return nil
	})
	return info, state
}

// elementAtPoint returns the deepest UI element whose bounding rectangle contains
// the point, descending the control view from the desktop root, together with its
// state. Both are read from the same element before it is released, so they
// describe one moment. STA-thread only.
func (d *Desktop) elementAtPoint(x, y int) (ElementInfo, ElementState) {
	if d.uia == nil || d.uia.automation == nil {
		return ElementInfo{}, ElementState{}
	}
	root, err := d.uia.automation.GetRootElement()
	if err != nil || root == nil {
		return ElementInfo{}, ElementState{}
	}
	defer root.Release()
	walker, err := d.uia.automation.Get_ControlViewWalker()
	if err != nil || walker == nil {
		return readElementInfo(root), readElementState(root)
	}
	defer walker.Release()

	cur := root
	var owned *accessibility.IUIAutomationElement // AddRef'd descent nodes we must free
	for range maxTreeDepth {
		child := smallestChildContaining(walker, cur, x, y)
		if child == nil {
			break
		}
		if owned != nil {
			owned.Release()
		}
		owned = child
		cur = child
	}
	info, state := readElementInfo(cur), readElementState(cur)
	if owned != nil {
		owned.Release()
	}
	return info, state
}

// cursorPoint reads the current pointer position in physical pixels. It is safe
// off the STA thread: GetCursorPos touches no COM.
func cursorPoint() (int, int) {
	var pt foundation.POINT
	if err := wm.GetCursorPos(&pt); err != nil {
		return 0, 0
	}
	return int(pt.X), int(pt.Y)
}

// smallestChildContaining returns the child of parent with the smallest area whose
// bounding rectangle contains the point, or nil. The returned element is AddRef'd
// (the caller releases it); every other child is released here. STA-thread only.
func smallestChildContaining(
	walker *accessibility.IUIAutomationTreeWalker,
	parent *accessibility.IUIAutomationElement,
	x, y int,
) *accessibility.IUIAutomationElement {
	child, err := walker.GetFirstChildElement(parent)
	if err != nil || child == nil {
		return nil
	}
	var best *accessibility.IUIAutomationElement
	var bestArea int
	for child != nil {
		keep := false
		if r, err := child.Get_CurrentBoundingRectangle(); err == nil {
			left, top, right, bottom := int(r.Left), int(r.Top), int(r.Right), int(r.Bottom)
			if x >= left && x < right && y >= top && y < bottom {
				area := (right - left) * (bottom - top)
				if best == nil || area < bestArea {
					if best != nil {
						best.Release()
					}
					best, bestArea, keep = child, area, true
				}
			}
		}
		next, nerr := walker.GetNextSiblingElement(child)
		if !keep {
			child.Release()
		}
		if nerr != nil {
			break
		}
		child = next
	}
	return best
}

// focusedIsPassword reports whether the currently focused element masks its
// input, treating "cannot tell" as yes. STA-thread only.
//
// Every failure path returns true, which is the opposite of what it used to do.
// Returning false on no UIA, no focused element, or an unsupported property meant
// "not known" became "not secret", and the characters were written to the journey
// file in clear -- a file created 0o644 with a nolint saying a journey is not a
// secret, which is true only while redaction holds.
//
// The cost of failing closed is a journey step recorded as redacted when it did
// not need to be, which an author can see and fix. The cost of failing open is a
// password in a file on disk.
func (d *Desktop) focusedIsPassword() bool {
	if d.uia == nil || d.uia.automation == nil {
		return true
	}
	el, err := d.uia.automation.GetFocusedElement()
	if err != nil || el == nil {
		return true
	}
	defer el.Release()
	b, err := el.Get_CurrentIsPassword()
	if err != nil {
		return true
	}
	return boolVal(b)
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
