//go:build windows && (amd64 || arm64)

package contain

import (
	"errors"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows/registry"

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
	// inUnset/outUnset record that the profile had *no configured value* before
	// isolation, which INetFwPolicy2 cannot express.
	//
	// Get_DefaultOutboundAction returns ALLOW for a profile whose value is absent
	// -- Windows' "NotConfigured" state -- so saving and restoring through that
	// API alone turns "nothing configured" into an explicit Allow, permanently,
	// on every profile, the first time containment runs. Lab testing caught this:
	// three profiles went NotConfigured -> explicit Allow and stayed there. The
	// registry is the only place the distinction survives, so it is read before
	// the change and the absent case is restored by deleting the value again.
	inUnset, outUnset bool
}

// firewallProfileKeys maps each profile to its local policy store key. The COM
// API has no notion of an unset action; these values do, by being absent.
var firewallProfileKeys = map[windowsfirewall.NET_FW_PROFILE_TYPE2]string{
	windowsfirewall.NET_FW_PROFILE2_DOMAIN:  `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile`,
	windowsfirewall.NET_FW_PROFILE2_PRIVATE: `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile`,
	windowsfirewall.NET_FW_PROFILE2_PUBLIC:  `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile`,
}

// actionIsUnset reports whether a profile's default action has no configured
// value. Errors are reported as "configured" so a registry problem can only ever
// cost fidelity on restore, never cause a value to be deleted that was really set.
func actionIsUnset(profile windowsfirewall.NET_FW_PROFILE_TYPE2, valueName string) bool {
	path, ok := firewallProfileKeys[profile]
	if !ok {
		return false
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer func() { _ = k.Close() }()
	if _, _, err := k.GetIntegerValue(valueName); err != nil {
		return errors.Is(err, registry.ErrNotExist)
	}
	return false
}

// clearAction deletes a profile's default-action value, returning it to
// NotConfigured. Used only where actionIsUnset said it was absent to begin with.
func clearAction(profile windowsfirewall.NET_FW_PROFILE_TYPE2, valueName string) error {
	path, ok := firewallProfileKeys[profile]
	if !ok {
		return nil
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()
	if err := k.DeleteValue(valueName); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}

// firewallIsolate flips every profile's default inbound and outbound actions to
// Block (loopback stays exempt by OS default) and returns a restore func that
// reinstates the saved actions. Requires elevation.
//
// The second return value reports what the firewall said the outbound action was
// *after* each write, read back through the same COM object. It exists because a
// successful Put proves only that the call did not error: lab testing audited
// killaction.done{isolate} on a run where a registry poll never observed the
// outbound default leaving Allow, and there was no way to tell a write that did
// not take effect from one whose effect the poll had missed. The registry turned
// out to be the wrong surface to watch -- Put_* goes to the firewall service,
// which does not necessarily persist it synchronously -- so the read-back has to
// come from the same API that did the writing. Audited with the trip.
func firewallIsolate() (func() error, []string, error) {
	var saved []savedProfile
	var observed []string
	err := WithCOMThread(func() error {
		policy, release, e := NewFwPolicy()
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
			saved = append(saved, savedProfile{
				profile:  p,
				in:       in,
				out:      out,
				inUnset:  actionIsUnset(p, "DefaultInboundAction"),
				outUnset: actionIsUnset(p, "DefaultOutboundAction"),
			})
			if e := policy.Put_DefaultInboundAction(p, windowsfirewall.NET_FW_ACTION_BLOCK); e != nil {
				return fmt.Errorf("block inbound (profile %d): %w", p, e)
			}
			if e := policy.Put_DefaultOutboundAction(p, windowsfirewall.NET_FW_ACTION_BLOCK); e != nil {
				return fmt.Errorf("block outbound (profile %d): %w", p, e)
			}
			// Read back through the same object, immediately. A Put that returns no
			// error has not necessarily changed anything.
			back, e := policy.Get_DefaultOutboundAction(p)
			switch {
			case e != nil:
				observed = append(observed, fmt.Sprintf("profile%d=read-error", p))
			case back == windowsfirewall.NET_FW_ACTION_BLOCK:
				observed = append(observed, fmt.Sprintf("profile%d=block", p))
			default:
				observed = append(observed, fmt.Sprintf("profile%d=NOT-BLOCKED(%d)", p, back))
			}
		}
		return nil
	})
	if err != nil {
		return nil, observed, err
	}
	restore := func() error {
		return WithCOMThread(func() error {
			policy, release, e := NewFwPolicy()
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
				// Then undo the value entirely where there was none before, so a
				// machine that inherited its firewall defaults still does. Done after
				// the Puts because the COM write is what recreates the value.
				if s.inUnset {
					if e := clearAction(s.profile, "DefaultInboundAction"); e != nil && firstErr == nil {
						firstErr = e
					}
				}
				if s.outUnset {
					if e := clearAction(s.profile, "DefaultOutboundAction"); e != nil && firstErr == nil {
						firstErr = e
					}
				}
			}
			return firstErr
		})
	}
	return restore, observed, nil
}

// NewFwPolicy instantiates INetFwPolicy2. The caller must run on a COM-
// initialized thread (use WithCOMThread) and call release when done.
//
// Exported because the egress enforcer creates firewall rules through the same
// object. Sharing this rather than standing up a second COM path keeps one
// answer to how this process talks to the firewall.
func NewFwPolicy() (*windowsfirewall.INetFwPolicy2, func(), error) {
	var unk *win32.IUnknown
	if err := com.CoCreateInstance(
		&clsidNetFwPolicy2,
		nil,
		com.CLSCTX_INPROC_SERVER,
		&windowsfirewall.IID_INetFwPolicy2,
		&unk,
	); err != nil {
		return nil, nil, fmt.Errorf("CoCreateInstance(NetFwPolicy2): %w", err)
	}
	if unk == nil {
		return nil, nil, fmt.Errorf("CoCreateInstance(NetFwPolicy2): nil interface")
	}
	policy := (*windowsfirewall.INetFwPolicy2)(unsafe.Pointer(unk))
	release := func() { (*com.IUnknown)(unsafe.Pointer(unk)).Release() }
	return policy, release, nil
}

// WithCOMThread runs fn on a dedicated OS thread with COM initialized (MTA), so
// the firewall calls are safe even while the engine's own STA thread is tearing
// down during a kill.
//
// Exported for the egress enforcer, which needs the same guarantee: its rule
// work must not depend on the desktop engine's thread being alive.
func WithCOMThread(fn func() error) error {
	return WithCOMThreadTimeout(fn, comThreadTimeout)
}

// comThreadTimeout bounds one COM firewall operation.
//
// Generous, because these calls are slow on a loaded machine and a spurious
// timeout mid-containment would be worse than waiting. It exists only so a hung
// call cannot block forever.
const comThreadTimeout = 30 * time.Second

// ErrCOMThreadTimeout reports a COM operation that did not return in time.
var ErrCOMThreadTimeout = errors.New("COM firewall operation timed out")

// WithCOMThreadTimeout is WithCOMThread with an explicit bound.
//
// The bound matters most on the kill path. firewallIsolate ran `return <-done`
// with nothing to interrupt it, so a stalled Windows Firewall service -- entirely
// plausible during the incident that triggered the kill -- blocked OnTrip
// indefinitely, and the finalize and abort steps that follow never ran. The
// forensic trail was then lost to a hang rather than to a reordering, which is the
// failure the ladder's ordering exists to prevent.
//
// On timeout the goroutine is abandoned rather than killed: it holds a locked OS
// thread inside a COM call and there is no safe way to reclaim it. Leaking one
// thread on the way to session termination is the right trade.
func WithCOMThreadTimeout(fn func() error, timeout time.Duration) error {
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
	if timeout <= 0 {
		return <-done
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case err := <-done:
		return err
	case <-t.C:
		return fmt.Errorf("%w after %s", ErrCOMThreadTimeout, timeout)
	}
}
