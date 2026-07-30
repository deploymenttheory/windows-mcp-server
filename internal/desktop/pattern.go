//go:build windows && (amd64 || arm64)

package desktop

import (
	"fmt"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	systemcom "github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/com"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/ui/accessibility"
)

// Pattern-based actions act on a UI Automation element directly through its
// control patterns (Invoke, Value, Toggle, SelectionItem, ExpandCollapse)
// rather than by synthesizing mouse/keyboard input. This is the reliable path
// preferred by RPA: it does not depend on the window being focused, unoccluded,
// or on-screen, and is not subject to UIPI input restrictions. Click/Type
// remain as the fallback for controls that expose no suitable pattern.

// elementForLabel returns the retained UIA element for a snapshot label, or nil.
// STA-thread use only.
func (d *Desktop) elementForLabel(label int) *accessibility.IUIAutomationElement {
	d.stateMu.Lock()
	defer d.stateMu.Unlock()
	if d.lastState == nil {
		return nil
	}
	for i := range d.lastState.Interactive {
		if d.lastState.Interactive[i].Label == label {
			return d.lastState.Interactive[i].element
		}
	}
	return nil
}

// withPattern resolves the labeled element's pattern and passes the pattern
// object to fn, releasing it afterwards. It runs on the engine STA thread.
func (d *Desktop) withPattern(
	label int,
	patternID accessibility.UIA_PATTERN_ID,
	name string,
	fn func(*systemcom.IUnknown) error,
) error {
	return d.Do(func() error {
		el := d.elementForLabel(label)
		if el == nil {
			return fmt.Errorf("label %d not found in the last Snapshot; take a fresh Snapshot first", label)
		}
		unk, err := el.GetCurrentPattern(patternID)
		if err != nil {
			return fmt.Errorf("get %s pattern: %w", name, err)
		}
		if unk == nil {
			return fmt.Errorf("element [%d] does not support %s", label, name)
		}
		defer unk.Release()
		return fn(unk)
	})
}

// InvokeLabel activates the labeled control via the Invoke pattern (buttons,
// links, menu items).
func (d *Desktop) InvokeLabel(label int) error {
	return d.withPattern(label, accessibility.UIA_InvokePatternId, "Invoke", func(unk *systemcom.IUnknown) error {
		pat := (*accessibility.IUIAutomationInvokePattern)(unsafe.Pointer(unk))
		return pat.Invoke()
	})
}

// SetValueLabel sets the labeled control's value via the Value pattern (text
// fields), without synthesizing keystrokes.
func (d *Desktop) SetValueLabel(label int, value string) error {
	return d.withPattern(label, accessibility.UIA_ValuePatternId, "SetValue", func(unk *systemcom.IUnknown) error {
		pat := (*accessibility.IUIAutomationValuePattern)(unsafe.Pointer(unk))
		bstr := foundation.SysAllocString(value)
		defer foundation.SysFreeString(bstr)
		return pat.SetValue(bstr)
	})
}

// ToggleLabel toggles the labeled control via the Toggle pattern (checkboxes,
// switches).
func (d *Desktop) ToggleLabel(label int) error {
	return d.withPattern(label, accessibility.UIA_TogglePatternId, "Toggle", func(unk *systemcom.IUnknown) error {
		pat := (*accessibility.IUIAutomationTogglePattern)(unsafe.Pointer(unk))
		return pat.Toggle()
	})
}

// SelectLabel selects the labeled item via the SelectionItem pattern (list
// items, radio buttons, tabs).
func (d *Desktop) SelectLabel(label int) error {
	return d.withPattern(
		label,
		accessibility.UIA_SelectionItemPatternId,
		"Select",
		func(unk *systemcom.IUnknown) error {
			pat := (*accessibility.IUIAutomationSelectionItemPattern)(unsafe.Pointer(unk))
			return pat.Select()
		},
	)
}

// ExpandLabel / CollapseLabel operate the ExpandCollapse pattern (combo boxes,
// tree items, expanders).
func (d *Desktop) ExpandLabel(label int) error {
	return d.withPattern(
		label,
		accessibility.UIA_ExpandCollapsePatternId,
		"Expand",
		func(unk *systemcom.IUnknown) error {
			pat := (*accessibility.IUIAutomationExpandCollapsePattern)(unsafe.Pointer(unk))
			return pat.Expand()
		},
	)
}

func (d *Desktop) CollapseLabel(label int) error {
	return d.withPattern(
		label,
		accessibility.UIA_ExpandCollapsePatternId,
		"Collapse",
		func(unk *systemcom.IUnknown) error {
			pat := (*accessibility.IUIAutomationExpandCollapsePattern)(unsafe.Pointer(unk))
			return pat.Collapse()
		},
	)
}

// ReadLabel returns the labeled element's current name and value (via the Value
// pattern when available), for verification and assertions. STA thread.
func (d *Desktop) ReadLabel(label int) (name, value string, err error) {
	err = d.Do(func() error {
		el := d.elementForLabel(label)
		if el == nil {
			return fmt.Errorf("label %d not found in the last Snapshot; take a fresh Snapshot first", label)
		}
		if b, e := el.Get_CurrentName(); e == nil {
			name = bstrToString(b)
		}
		if unk, e := el.GetCurrentPattern(accessibility.UIA_ValuePatternId); e == nil && unk != nil {
			defer unk.Release()
			pat := (*accessibility.IUIAutomationValuePattern)(unsafe.Pointer(unk))
			if b, e := pat.Get_CurrentValue(); e == nil {
				value = bstrToString(b)
			}
		}
		return nil
	})
	return name, value, err
}
