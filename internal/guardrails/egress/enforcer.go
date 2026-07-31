package egress

// Enforcer is the OS actuation that stops a workload going around the proxy,
// kept behind an interface for the same reason SystemActuator is: the decision
// and the lifecycle stay testable with fakes, on any platform, with no firewall
// and no elevation.
//
// Phase 1 ships only NoEnforcer. The Windows implementation — outbound-block
// rules scoped to named applications, and the opt-in machine-wide block — lands
// behind this interface without the rest of the package changing.
type Enforcer interface {
	// Elevated reports whether this process can change firewall state. A policy
	// that asks for enforcement without it is refused at startup rather than
	// served in a weaker form than the document describes.
	Elevated() bool
	// Apply installs the rules described by spec and returns the undo. It must
	// persist its recovery state before making any change, so a crash mid-way
	// is recoverable by the next start.
	Apply(spec EnforceSpec) (restore func() error, err error)
	// Recover undoes whatever a previously crashed run left behind and reports
	// how many rules it removed. It runs on every startup, including when the
	// current policy disables egress: state left by an earlier session is
	// exactly what nothing else would clean up.
	Recover() (removed int, err error)
	// Suspend weakens egress without restoring anything, for the kill path.
	//
	// Containment flips the machine's default outbound action to block, but the
	// allow rules global mode installs beat that default — so this server's own
	// binary and the exempted services would keep their route out during an
	// incident. Disabling those rules closes it. Nothing is restored here,
	// because undoing state in Finalize could countermand the isolation the
	// kill ladder has just applied.
	Suspend() error
}

// EnforceSpec is what the OS layer is asked to arrange.
type EnforceSpec struct {
	// ProxyAddr is the loopback address the blocked applications must still be
	// able to reach. Windows Firewall does not filter loopback, which is what
	// makes scoped blocking work at all.
	ProxyAddr string
	// Applications are full image paths to block outbound.
	Applications []string
	// GlobalBlock flips the machine's default outbound action, with the service
	// exception set that keeps DNS, DHCP, NCSI and update working.
	GlobalBlock bool
	// AllowPorts bounds the proxy's own allow rule under GlobalBlock, so the
	// firewall grant is no broader than the allowlist the proxy enforces.
	AllowPorts []int
	// SetSystemProxy points this user's WinINET settings at ProxyAddr.
	SetSystemProxy bool
}

// specNeedsAction reports whether a spec asks the OS layer to do anything at
// all. Split out from Apply so the decision is testable without mutating the
// machine the test runs on.
func specNeedsAction(spec EnforceSpec) bool {
	return specNeedsElevation(spec) || spec.SetSystemProxy
}

// specNeedsElevation reports whether a spec requires an elevated process.
//
// Only the firewall work does. Pointing this user's WinINET settings at the
// proxy is an HKCU write, so gating it on elevation would refuse a policy that
// is perfectly performable.
func specNeedsElevation(spec EnforceSpec) bool {
	return len(spec.Applications) > 0 || spec.GlobalBlock
}

// NoEnforcer performs no OS actuation. It is the honest implementation for the
// proxy-only tier and for every non-Windows build: the proxy constrains what is
// configured to use it, and nothing more.
type NoEnforcer struct{}

func (NoEnforcer) Elevated() bool { return false }

func (NoEnforcer) Apply(EnforceSpec) (func() error, error) {
	return func() error { return nil }, nil
}

func (NoEnforcer) Recover() (int, error) { return 0, nil }

func (NoEnforcer) Suspend() error { return nil }
