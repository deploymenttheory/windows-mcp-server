//go:build windows && (amd64 || arm64)

package desktop

import (
	"fmt"
	"strings"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/ui/accessibility"
)

// LabeledElement is an interactive element assigned a stable label within a
// snapshot, together with its click point (the center of its bounding rect).
type LabeledElement struct {
	Label   int
	Info    ElementInfo
	CenterX int
	CenterY int

	// element is the live UI Automation element, retained (AddRef'd) so that
	// pattern-based actions (Invoke/SetValue/Toggle/...) can act on it directly
	// rather than via synthetic input. It is released when the snapshot is
	// replaced (see releaseStateElements). STA-thread use only.
	element *accessibility.IUIAutomationElement
}

const (
	// maxTreeNodes bounds the total number of elements visited across a whole
	// snapshot, so a pathological UI cannot make traversal unbounded.
	maxTreeNodes = 2500
	// maxTreeDepth bounds recursion depth.
	maxTreeDepth = 40
)

// treeBuilder accumulates the labeled interactive elements and a semantic tree
// rendering across one or more windows. It uses the control-view tree walker.
type treeBuilder struct {
	walker      *accessibility.IUIAutomationTreeWalker
	interactive []LabeledElement
	lines       []string
	nodes       int
}

// visitWindow renders one window's subtree, appending to the builder. The
// window element is not released here (the caller owns it).
func (tb *treeBuilder) visitWindow(window *accessibility.IUIAutomationElement, w WindowInfo) {
	fg := ""
	if w.IsForeground {
		fg = " (focused)"
	}
	min := ""
	if w.Minimized {
		min = " (minimized)"
	}
	tb.lines = append(tb.lines, fmt.Sprintf("Window: %q [pid %d]%s%s", w.Title, w.ProcessID, fg, min))
	tb.visitChildren(window, 1)
}

func (tb *treeBuilder) visitChildren(parent *accessibility.IUIAutomationElement, depth int) {
	if depth > maxTreeDepth || tb.nodes >= maxTreeNodes {
		return
	}
	child, err := tb.walker.GetFirstChildElement(parent)
	if err != nil || child == nil {
		return
	}
	for child != nil {
		tb.visit(child, depth)
		next, err := tb.walker.GetNextSiblingElement(child)
		child.Release()
		if err != nil || tb.nodes >= maxTreeNodes {
			break
		}
		child = next
	}
}

func (tb *treeBuilder) visit(el *accessibility.IUIAutomationElement, depth int) {
	tb.nodes++
	info := readElementInfo(el)
	ct := accessibility.UIA_CONTROLTYPE_ID(info.ControlTypeID)
	indent := strings.Repeat("  ", depth)

	interactive := isInteractiveControlType(ct) && info.Enabled && !info.Offscreen && !info.Rect.Empty()
	switch {
	case interactive:
		label := len(tb.interactive)
		cx, cy := info.Rect.Center()
		// Retain the element so pattern-based actions can use it later. The
		// caller (visitChildren) releases its own reference after this returns;
		// the AddRef here keeps ours alive until the snapshot is replaced.
		el.AddRef()
		tb.interactive = append(tb.interactive, LabeledElement{
			Label: label, Info: info, CenterX: cx, CenterY: cy, element: el,
		})
		tb.lines = append(tb.lines, fmt.Sprintf("%s[%d] %s %q (%d,%d)", indent, label, info.ControlType, info.Name, cx, cy))
	case info.Name != "":
		// Informative/structural node with a name: include for context.
		tb.lines = append(tb.lines, fmt.Sprintf("%s%s %q", indent, info.ControlType, info.Name))
	}

	tb.visitChildren(el, depth+1)
}
