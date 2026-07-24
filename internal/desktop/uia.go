//go:build windows && (amd64 || arm64)

package desktop

import (
	"fmt"
	"unsafe"

	win32 "github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/com"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/ui/accessibility"
)

// clsidCUIAutomation is the class identifier of the UI Automation client
// coclass (CUIAutomation). The bindings emit it only as an empty marker with no
// GUID constant, so we declare it here — the same technique the go-bindings-wmi
// runtime uses for the WbemLocator CLSID.
var clsidCUIAutomation = win32.GUID{
	Data1: 0xff48dba4,
	Data2: 0x60ef,
	Data3: 0x4201,
	Data4: [8]byte{0xaa, 0x87, 0x54, 0x10, 0x3e, 0xef, 0x59, 0x4e},
}

// uiaClient wraps the root IUIAutomation object. It must only be used from the
// engine's STA thread (via Desktop.Do).
type uiaClient struct {
	automation *accessibility.IUIAutomation
}

// newUIAClient creates the UI Automation client. It must run on the STA thread
// after COM has been initialized.
func newUIAClient() (*uiaClient, error) {
	var unk *win32.IUnknown
	err := com.CoCreateInstance(&clsidCUIAutomation, nil, com.CLSCTX_INPROC_SERVER, &accessibility.IID_IUIAutomation, &unk)
	if err != nil {
		return nil, fmt.Errorf("CoCreateInstance(CUIAutomation): %w", err)
	}
	if unk == nil {
		return nil, fmt.Errorf("CoCreateInstance(CUIAutomation): returned nil interface")
	}
	// Every generated COM interface shares IUnknown's one-word vtable layout, so
	// the out-param casts directly to *IUIAutomation.
	automation := (*accessibility.IUIAutomation)(unsafe.Pointer(unk))
	return &uiaClient{automation: automation}, nil
}

// close releases the automation object. Safe to call on a nil client.
func (c *uiaClient) close() {
	if c == nil || c.automation == nil {
		return
	}
	c.automation.Release()
	c.automation = nil
}

// rootElement returns the desktop root element. Caller owns the returned
// element and must Release it.
func (c *uiaClient) rootElement() (*accessibility.IUIAutomationElement, error) {
	root, err := c.automation.GetRootElement()
	if err != nil {
		return nil, fmt.Errorf("GetRootElement: %w", err)
	}
	if root == nil {
		return nil, fmt.Errorf("GetRootElement: nil element")
	}
	return root, nil
}

// RootInfo returns the UI Automation desktop root element's name and its direct
// child count. It is a lightweight smoke test confirming that COM, DPI
// awareness, and the UIA client are all working on the engine thread.
func (d *Desktop) RootInfo() (name string, childCount int, err error) {
	err = d.Do(func() error {
		root, e := d.client().rootElement()
		if e != nil {
			return e
		}
		defer root.Release()

		nameBSTR, e := root.Get_CurrentName()
		if e != nil {
			return fmt.Errorf("root name: %w", e)
		}
		name = bstrToString(nameBSTR)

		cond, e := d.client().automation.CreateTrueCondition()
		if e != nil {
			return fmt.Errorf("CreateTrueCondition: %w", e)
		}
		defer cond.Release()

		arr, e := root.FindAll(accessibility.TreeScope_Children, cond)
		if e != nil {
			return fmt.Errorf("FindAll children: %w", e)
		}
		if arr != nil {
			defer arr.Release()
			n, e := arr.Get_Length()
			if e != nil {
				return fmt.Errorf("children length: %w", e)
			}
			childCount = int(n)
		}
		return nil
	})
	return name, childCount, err
}
