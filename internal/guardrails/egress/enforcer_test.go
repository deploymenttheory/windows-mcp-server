package egress

import (
	"errors"
	"testing"
)

// fakeEnforcer stands in for the OS layer, so the lifecycle around enforcement
// is testable without a firewall or elevation.
type fakeEnforcer struct {
	elevated     bool
	applied      []EnforceSpec
	restores     int
	recovered    int
	suspends     int
	applyErr     error
	restoreErr   error
	recoverError error
}

func (f *fakeEnforcer) Suspend() error {
	f.suspends++
	return nil
}

func (f *fakeEnforcer) Elevated() bool { return f.elevated }

func (f *fakeEnforcer) Apply(spec EnforceSpec) (func() error, error) {
	if f.applyErr != nil {
		return nil, f.applyErr
	}
	f.applied = append(f.applied, spec)
	return func() error {
		f.restores++
		return f.restoreErr
	}, nil
}

func (f *fakeEnforcer) Recover() (int, error) { return f.recovered, f.recoverError }

// Enforcer is satisfied by both the fake and the real implementations.
var (
	_ Enforcer = (*fakeEnforcer)(nil)
	_ Enforcer = NoEnforcer{}
	_ Enforcer = WindowsEnforcer{}
)

// TestNoEnforcerIsHonestlyUnprivileged pins the property the proxy-only tier
// depends on: it claims nothing it cannot do, so a policy asking for
// enforcement is refused rather than silently downgraded.
func TestNoEnforcerIsHonestlyUnprivileged(t *testing.T) {
	var e NoEnforcer
	if e.Elevated() {
		t.Error("NoEnforcer must not claim elevation")
	}
	restore, err := e.Apply(EnforceSpec{Applications: []string{`C:\a.exe`}})
	if err != nil {
		t.Fatalf("NoEnforcer.Apply should be a no-op: %v", err)
	}
	if err := restore(); err != nil {
		t.Errorf("NoEnforcer restore should be a no-op: %v", err)
	}
	if n, err := e.Recover(); n != 0 || err != nil {
		t.Errorf("NoEnforcer.Recover = (%d, %v), want (0, nil)", n, err)
	}
	if err := e.Suspend(); err != nil {
		t.Errorf("NoEnforcer.Suspend should be a no-op: %v", err)
	}
}

// TestEnforcerRefusesWithoutElevation covers the deliberate asymmetry with the
// kill ladder: containment degrades when it cannot act, enforcement does not.
func TestEnforcerRefusesWithoutElevation(t *testing.T) {
	var e WindowsEnforcer
	if e.Elevated() {
		t.Skip("test host is elevated; the refusal path cannot be exercised here")
	}
	_, err := e.Apply(EnforceSpec{Applications: []string{`C:\Windows\System32\curl.exe`}})
	if !errors.Is(err, ErrNotElevated) {
		t.Errorf("Apply without elevation = %v, want ErrNotElevated", err)
	}
}

// TestEnforcerWithNoApplicationsIsANoOp keeps the proxy-only tier free of
// firewall work, elevated or not.
func TestEnforcerWithNoApplicationsIsANoOp(t *testing.T) {
	var e WindowsEnforcer
	restore, err := e.Apply(EnforceSpec{ProxyAddr: "127.0.0.1:8181"})
	if err != nil {
		t.Fatalf("an empty spec should not touch the firewall: %v", err)
	}
	if err := restore(); err != nil {
		t.Errorf("restore of an empty spec: %v", err)
	}
}

// TestSystemProxyIsNotGatedOnFirewallWork covers a real regression: the
// firewall early-return used to swallow set_system_proxy, so a proxy-only
// policy asking for it silently configured nothing. Pointing WinINET at the
// listener needs no elevation and must work on its own.
func TestSystemProxyIsNotGatedOnFirewallWork(t *testing.T) {
	var e WindowsEnforcer
	if e.Elevated() {
		t.Skip("test host is elevated; this checks the unelevated path")
	}
	_, err := e.Apply(EnforceSpec{ProxyAddr: "127.0.0.1:8181", SetSystemProxy: true})
	if errors.Is(err, ErrNotElevated) {
		t.Error("set_system_proxy writes HKCU and must not require elevation")
	}
	// It either succeeded (and the caller owns the restore) or failed for a
	// registry reason; what it must not do is refuse for want of privilege, nor
	// silently do nothing.
}
