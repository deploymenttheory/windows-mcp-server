//go:build windows && (amd64 || arm64)

package guardrails

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	win32 "github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networkmanagement/windowsfirewall"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/com"
)

// clsidNetFwPolicy2 is the class identifier of the HNetCfg.FwPolicy2 coclass.
// The bindings expose IID_INetFwPolicy2 but not this CLSID, so it is declared
// here (same technique as the CUIAutomation CLSID in internal/desktop/uia.go).
var clsidNetFwPolicy2 = win32.GUID{
	Data1: 0xe2b3c97f,
	Data2: 0x6ae1,
	Data3: 0x41ac,
	Data4: [8]byte{0x81, 0x7a, 0xf6, 0xf9, 0x21, 0x66, 0xd7, 0xdd},
}

// isolationProfiles are the firewall profiles whose default actions are flipped
// to Block during isolation.
var isolationProfiles = []windowsfirewall.NET_FW_PROFILE_TYPE2{
	windowsfirewall.NET_FW_PROFILE2_DOMAIN,
	windowsfirewall.NET_FW_PROFILE2_PRIVATE,
	windowsfirewall.NET_FW_PROFILE2_PUBLIC,
}

type savedProfile struct {
	profile windowsfirewall.NET_FW_PROFILE_TYPE2
	in, out windowsfirewall.NET_FW_ACTION
}

// firewallIsolate flips every profile's default inbound and outbound actions to
// Block (loopback stays exempt by OS default) and returns a restore func that
// reinstates the saved actions. Requires elevation.
func firewallIsolate() (func() error, error) {
	var saved []savedProfile
	err := withCOMThread(func() error {
		policy, release, e := newFwPolicy()
		if e != nil {
			return e
		}
		defer release()
		for _, p := range isolationProfiles {
			in, e1 := policy.Get_DefaultInboundAction(p)
			out, e2 := policy.Get_DefaultOutboundAction(p)
			if e1 != nil || e2 != nil {
				return fmt.Errorf("read firewall defaults (profile %d): %w", p, errors.Join(e1, e2))
			}
			saved = append(saved, savedProfile{p, in, out})
			if e := policy.Put_DefaultInboundAction(p, windowsfirewall.NET_FW_ACTION_BLOCK); e != nil {
				return fmt.Errorf("block inbound (profile %d): %w", p, e)
			}
			if e := policy.Put_DefaultOutboundAction(p, windowsfirewall.NET_FW_ACTION_BLOCK); e != nil {
				return fmt.Errorf("block outbound (profile %d): %w", p, e)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	restore := func() error {
		return withCOMThread(func() error {
			policy, release, e := newFwPolicy()
			if e != nil {
				return e
			}
			defer release()
			var firstErr error
			for _, s := range saved {
				if e := policy.Put_DefaultInboundAction(s.profile, s.in); e != nil && firstErr == nil {
					firstErr = e
				}
				if e := policy.Put_DefaultOutboundAction(s.profile, s.out); e != nil && firstErr == nil {
					firstErr = e
				}
			}
			return firstErr
		})
	}
	return restore, nil
}

// newFwPolicy instantiates INetFwPolicy2. The caller must run on a COM-
// initialized thread (use withCOMThread) and call release when done.
func newFwPolicy() (*windowsfirewall.INetFwPolicy2, func(), error) {
	var unk *win32.IUnknown
	if err := com.CoCreateInstance(&clsidNetFwPolicy2, nil, com.CLSCTX_INPROC_SERVER, &windowsfirewall.IID_INetFwPolicy2, &unk); err != nil {
		return nil, nil, fmt.Errorf("CoCreateInstance(NetFwPolicy2): %w", err)
	}
	if unk == nil {
		return nil, nil, fmt.Errorf("CoCreateInstance(NetFwPolicy2): nil interface")
	}
	policy := (*windowsfirewall.INetFwPolicy2)(unsafe.Pointer(unk))
	release := func() { (*com.IUnknown)(unsafe.Pointer(unk)).Release() }
	return policy, release, nil
}

// withCOMThread runs fn on a dedicated OS thread with COM initialized (MTA), so
// the firewall calls are safe even while the engine's own STA thread is tearing
// down during a kill.
func withCOMThread(fn func() error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		// COINIT_MULTITHREADED (0). On a fresh thread this succeeds; a benign
		// RPC_E_CHANGED_MODE is ignored (we still proceed and CoUninitialize).
		_, _ = com.CoInitializeEx(0)
		defer com.CoUninitialize()
		done <- fn()
	}()
	return <-done
}
