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
	// Recover undoes whatever a previously crashed run left behind. It runs on
	// every startup, including when the current policy disables egress: state
	// left by an earlier session is exactly what nothing else would clean up.
	Recover() error
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
}

// NoEnforcer performs no OS actuation. It is the honest implementation for the
// proxy-only tier and for every non-Windows build: the proxy constrains what is
// configured to use it, and nothing more.
type NoEnforcer struct{}

func (NoEnforcer) Elevated() bool { return false }

func (NoEnforcer) Apply(EnforceSpec) (func() error, error) {
	return func() error { return nil }, nil
}

func (NoEnforcer) Recover() error { return nil }
