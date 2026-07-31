//go:build !windows || !(amd64 || arm64)

package egress

import "errors"

// ErrNotElevated keeps the error identity available off Windows, so callers and
// tests can match on it without a build tag of their own.
var ErrNotElevated = errors.New("egress enforcement requires an elevated process")

// WindowsEnforcer is the no-op stand-in on platforms that have no Windows
// Firewall. It reports itself unelevated, so the startup path refuses a policy
// asking for enforcement rather than pretending to apply it — the same answer an
// unelevated Windows process gets, and for the same reason.
type WindowsEnforcer struct {
	Logger any
}

func (WindowsEnforcer) Elevated() bool { return false }

func (WindowsEnforcer) Apply(spec EnforceSpec) (func() error, error) {
	if len(spec.Applications) == 0 && !spec.GlobalBlock {
		return func() error { return nil }, nil
	}
	return nil, ErrNotElevated
}

func (WindowsEnforcer) Recover() (int, error) { return 0, nil }

func (WindowsEnforcer) Suspend() error { return nil }
