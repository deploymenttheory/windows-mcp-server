//go:build windows && (amd64 || arm64)

package desktop

import (
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/ui/accessibility"
)

// Rect is a screen rectangle in physical pixels (the engine is per-monitor-DPI
// aware, so these are true device coordinates).
type Rect struct {
	Left, Top, Right, Bottom int
}

// Width returns the rectangle width.
func (r Rect) Width() int { return r.Right - r.Left }

// Height returns the rectangle height.
func (r Rect) Height() int { return r.Bottom - r.Top }

// Empty reports whether the rectangle has no area.
func (r Rect) Empty() bool { return r.Width() <= 0 || r.Height() <= 0 }

// Center returns the rectangle's center point.
func (r Rect) Center() (x, y int) {
	return r.Left + r.Width()/2, r.Top + r.Height()/2
}

// ElementInfo is a snapshot of a UI Automation element's key properties, read
// off the element while it is alive so the element handle can then be released.
type ElementInfo struct {
	Name          string
	ControlType   string
	ControlTypeID int32
	ClassName     string
	AutomationID  string
	Rect          Rect
	Enabled       bool
	Offscreen     bool
	ProcessID     int32
	// IsPassword marks a field that masks its input (a password box). The journey
	// recorder reads it to redact keystrokes typed into such a field.
	IsPassword bool
}

// readElementInfo reads the commonly-needed properties of a UIA element. It
// tolerates individual property failures (some elements do not implement every
// property) by leaving the corresponding field at its zero value. It must run
// on the engine STA thread.
func readElementInfo(el *accessibility.IUIAutomationElement) ElementInfo {
	var info ElementInfo
	if el == nil {
		return info
	}

	if b, err := el.Get_CurrentName(); err == nil {
		info.Name = bstrToString(b)
	}
	if ct, err := el.Get_CurrentControlType(); err == nil {
		info.ControlTypeID = int32(ct)
		info.ControlType = controlTypeName(ct)
	}
	if b, err := el.Get_CurrentClassName(); err == nil {
		info.ClassName = bstrToString(b)
	}
	if b, err := el.Get_CurrentAutomationId(); err == nil {
		info.AutomationID = bstrToString(b)
	}
	if r, err := el.Get_CurrentBoundingRectangle(); err == nil {
		info.Rect = Rect{Left: int(r.Left), Top: int(r.Top), Right: int(r.Right), Bottom: int(r.Bottom)}
	}
	if b, err := el.Get_CurrentIsEnabled(); err == nil {
		info.Enabled = boolVal(b)
	}
	if b, err := el.Get_CurrentIsOffscreen(); err == nil {
		info.Offscreen = boolVal(b)
	}
	if pid, err := el.Get_CurrentProcessId(); err == nil {
		info.ProcessID = pid
	}
	if b, err := el.Get_CurrentIsPassword(); err == nil {
		info.IsPassword = boolVal(b)
	}
	return info
}

// interactiveControlTypes is the set of UIA control types treated as directly
// interactive (clickable/typeable). This is a pragmatic subset of the Python
// implementation's classification; it covers the common desktop and web
// controls and can be extended.
var interactiveControlTypes = map[accessibility.UIA_CONTROLTYPE_ID]bool{
	accessibility.UIA_ButtonControlTypeId:      true,
	accessibility.UIA_CheckBoxControlTypeId:    true,
	accessibility.UIA_ComboBoxControlTypeId:    true,
	accessibility.UIA_EditControlTypeId:        true,
	accessibility.UIA_HyperlinkControlTypeId:   true,
	accessibility.UIA_ListItemControlTypeId:    true,
	accessibility.UIA_MenuItemControlTypeId:    true,
	accessibility.UIA_RadioButtonControlTypeId: true,
	accessibility.UIA_TabItemControlTypeId:     true,
	accessibility.UIA_SplitButtonControlTypeId: true,
	accessibility.UIA_TreeItemControlTypeId:    true,
	accessibility.UIA_SliderControlTypeId:      true,
	accessibility.UIA_SpinnerControlTypeId:     true,
	accessibility.UIA_MenuControlTypeId:        true,
}

// isInteractiveControlType reports whether a control type is directly interactive.
func isInteractiveControlType(ct accessibility.UIA_CONTROLTYPE_ID) bool {
	return interactiveControlTypes[ct]
}

// controlTypeNames maps UIA control type IDs to short human-readable names.
var controlTypeNames = map[accessibility.UIA_CONTROLTYPE_ID]string{
	accessibility.UIA_ButtonControlTypeId:       "Button",
	accessibility.UIA_CalendarControlTypeId:     "Calendar",
	accessibility.UIA_CheckBoxControlTypeId:     "CheckBox",
	accessibility.UIA_ComboBoxControlTypeId:     "ComboBox",
	accessibility.UIA_EditControlTypeId:         "Edit",
	accessibility.UIA_HyperlinkControlTypeId:    "Hyperlink",
	accessibility.UIA_ImageControlTypeId:        "Image",
	accessibility.UIA_ListItemControlTypeId:     "ListItem",
	accessibility.UIA_ListControlTypeId:         "List",
	accessibility.UIA_MenuControlTypeId:         "Menu",
	accessibility.UIA_MenuBarControlTypeId:      "MenuBar",
	accessibility.UIA_MenuItemControlTypeId:     "MenuItem",
	accessibility.UIA_ProgressBarControlTypeId:  "ProgressBar",
	accessibility.UIA_RadioButtonControlTypeId:  "RadioButton",
	accessibility.UIA_ScrollBarControlTypeId:    "ScrollBar",
	accessibility.UIA_SliderControlTypeId:       "Slider",
	accessibility.UIA_SpinnerControlTypeId:      "Spinner",
	accessibility.UIA_StatusBarControlTypeId:    "StatusBar",
	accessibility.UIA_TabControlTypeId:          "Tab",
	accessibility.UIA_TabItemControlTypeId:      "TabItem",
	accessibility.UIA_TextControlTypeId:         "Text",
	accessibility.UIA_ToolBarControlTypeId:      "ToolBar",
	accessibility.UIA_ToolTipControlTypeId:      "ToolTip",
	accessibility.UIA_TreeControlTypeId:         "Tree",
	accessibility.UIA_TreeItemControlTypeId:     "TreeItem",
	accessibility.UIA_CustomControlTypeId:       "Custom",
	accessibility.UIA_GroupControlTypeId:        "Group",
	accessibility.UIA_ThumbControlTypeId:        "Thumb",
	accessibility.UIA_DataGridControlTypeId:     "DataGrid",
	accessibility.UIA_DataItemControlTypeId:     "DataItem",
	accessibility.UIA_DocumentControlTypeId:     "Document",
	accessibility.UIA_SplitButtonControlTypeId:  "SplitButton",
	accessibility.UIA_WindowControlTypeId:       "Window",
	accessibility.UIA_PaneControlTypeId:         "Pane",
	accessibility.UIA_HeaderControlTypeId:       "Header",
	accessibility.UIA_HeaderItemControlTypeId:   "HeaderItem",
	accessibility.UIA_TableControlTypeId:        "Table",
	accessibility.UIA_TitleBarControlTypeId:     "TitleBar",
	accessibility.UIA_SeparatorControlTypeId:    "Separator",
	accessibility.UIA_SemanticZoomControlTypeId: "SemanticZoom",
	accessibility.UIA_AppBarControlTypeId:       "AppBar",
}

// controlTypeName returns a short name for a control type ID, or "Unknown".
func controlTypeName(ct accessibility.UIA_CONTROLTYPE_ID) string {
	if name, ok := controlTypeNames[ct]; ok {
		return name
	}
	return "Unknown"
}
