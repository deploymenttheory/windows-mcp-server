//go:build windows && (amd64 || arm64)

package desktop

import (
	"fmt"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/ui/accessibility"
)

// ElementState is what an assertion can read about one element. It is a snapshot
// of the properties and patterns that carry state, taken together on the STA
// thread so the fields describe one consistent moment rather than several.
//
// The Has* flags distinguish "false" from "the control does not have this kind of
// state": asserting that a Button is unchecked should report that a Button has no
// toggle state, not that it is unchecked.
type ElementState struct {
	Name        string
	ControlType string
	Value       string
	Enabled     bool
	Checked     bool
	Selected    bool
	Focused     bool

	HasValue     bool
	HasToggle    bool
	HasSelection bool
}

// ElementState reads the current state of a labeled element. STA thread.
func (d *Desktop) ElementState(label int) (ElementState, error) {
	var st ElementState
	err := d.Do(func() error {
		el := d.elementForLabel(label)
		if el == nil {
			return fmt.Errorf("%w: %d", ErrLabelNotFound, label)
		}
		if b, e := el.Get_CurrentName(); e == nil {
			st.Name = bstrToString(b)
		}
		if ct, e := el.Get_CurrentControlType(); e == nil {
			st.ControlType = controlTypeName(ct)
		}
		if b, e := el.Get_CurrentIsEnabled(); e == nil {
			st.Enabled = boolVal(b)
		}
		if b, e := el.Get_CurrentHasKeyboardFocus(); e == nil {
			st.Focused = boolVal(b)
		}
		readValue(el, &st)
		readToggle(el, &st)
		readSelection(el, &st)
		return nil
	})
	return st, err
}

// readValue reads the Value pattern, when the element exposes one. STA thread.
func readValue(el *accessibility.IUIAutomationElement, st *ElementState) {
	unk, err := el.GetCurrentPattern(accessibility.UIA_ValuePatternId)
	if err != nil || unk == nil {
		return
	}
	defer unk.Release()
	pat := (*accessibility.IUIAutomationValuePattern)(unsafe.Pointer(unk))
	if b, e := pat.Get_CurrentValue(); e == nil {
		st.Value, st.HasValue = bstrToString(b), true
	}
}

// readToggle reads the Toggle pattern. An indeterminate checkbox reports as not
// checked: a tri-state control is genuinely neither, and reporting it as checked
// would make an is_true assertion pass on a box the user has not ticked.
func readToggle(el *accessibility.IUIAutomationElement, st *ElementState) {
	unk, err := el.GetCurrentPattern(accessibility.UIA_TogglePatternId)
	if err != nil || unk == nil {
		return
	}
	defer unk.Release()
	pat := (*accessibility.IUIAutomationTogglePattern)(unsafe.Pointer(unk))
	if s, e := pat.Get_CurrentToggleState(); e == nil {
		st.Checked, st.HasToggle = s == accessibility.ToggleState_On, true
	}
}

// readSelection reads the SelectionItem pattern. STA thread.
func readSelection(el *accessibility.IUIAutomationElement, st *ElementState) {
	unk, err := el.GetCurrentPattern(accessibility.UIA_SelectionItemPatternId)
	if err != nil || unk == nil {
		return
	}
	defer unk.Release()
	pat := (*accessibility.IUIAutomationSelectionItemPattern)(unsafe.Pointer(unk))
	if b, e := pat.Get_CurrentIsSelected(); e == nil {
		st.Selected, st.HasSelection = boolVal(b), true
	}
}
