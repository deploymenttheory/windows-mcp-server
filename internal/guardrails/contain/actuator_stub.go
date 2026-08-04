//go:build !windows

package contain

import (
	"log/slog"
	"time"
)

// stubActuator is the non-Windows no-op SystemActuator so the security core
// builds and unit-tests on Linux (CI). Every action is a safe no-op and
// elevation is always false, so the best-effort-degrade paths are what run.
type stubActuator struct{}

// NewSystemActuator returns the platform SystemActuator. On non-Windows it is a
// no-op stub.
func NewSystemActuator(_ *slog.Logger) SystemActuator { return stubActuator{} }

func (stubActuator) Elevated() bool { return false }
func (stubActuator) IsolateNetwork() (func() error, []string, error) {
	return func() error { return nil }, nil, nil
}
func (stubActuator) KillProcesses(_ []string) []error         { return nil }
func (stubActuator) LockWorkstation() error                   { return nil }
func (stubActuator) Shutdown(_ string, _ time.Duration) error { return nil }

// CurrentUserIsAdmin is always false off-Windows (non-admin path).
func CurrentUserIsAdmin() bool { return false }
