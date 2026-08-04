//go:build windows && (amd64 || arm64)

package egress

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The recovery state exists because the rules outlive the process that made
// them. A session killed with Stop-Process, a machine powered off mid-run, or a
// panic past the deferred cleanup all leave firewall rules installed with
// nothing left to explain them — and the application an operator blocked stays
// blocked, with no server running to proxy it.
//
// The names cannot be re-derived at the next start: they come from the
// application list, and the policy may have changed or egress may now be off.
// So they are written down, before any rule is created, and the next start
// removes whatever the file names.
const (
	stateDirName  = "WindowsMCP"
	stateFileName = "egress-rules.json"
)

// enforcementState is what a future run needs to undo this one.
type enforcementState struct {
	// PID and Listen are diagnostic: an operator finding rules on a machine
	// wants to know what put them there.
	PID       int      `json:"pid"`
	Listen    string   `json:"listen"`
	Group     string   `json:"group"`
	RuleNames []string `json:"rule_names"`
	// GlobalBlock records that the machine's default outbound action was
	// changed. This is the field that matters most in a recovery: rules can be
	// left behind harmlessly, but a machine left default-deny with nothing
	// running to proxy it has no working network at all.
	GlobalBlock bool `json:"global_block,omitempty"`
	// SavedOutbound is the per-profile default action to put back. It records
	// what was found rather than assuming Allow, so an operator whose machine
	// already blocked outbound by policy does not have that quietly undone.
	SavedOutbound []savedOutbound `json:"saved_outbound,omitempty"`
	// SystemProxy is the WinINET configuration to put back, when the policy
	// pointed this user's settings at the proxy.
	SystemProxy *savedProxySettings `json:"system_proxy,omitempty"`
}

// stateDir is ProgramData rather than the user profile: the rules are
// machine-wide, so what records them has to be too.
func stateDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = os.Getenv("ALLUSERSPROFILE")
	}
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, stateDirName)
}

func statePath() string { return filepath.Join(stateDir(), stateFileName) }

// writeState records the rules about to be created. It is called before the
// first rule is added, never after: a crash between writing and creating leaves
// a file naming rules that do not exist, and removing a rule that is not there
// is a no-op. The reverse order would leave real rules with nothing recording
// them.
func writeState(state enforcementState) error {
	if err := ensureStateDir(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode egress state: %w", err)
	}
	// The mode is nominal on Windows — Go synthesizes a Unix mode that means
	// nothing here. The real access control is the directory's DACL, set by
	// ensureStateDir. The mode is written restrictively anyway so the intent is
	// not misread: this file describes machine state, and only an elevated
	// process should rewrite it.
	if err := os.WriteFile(statePath(), append(raw, '\n'), 0o600); err != nil {
		return fmt.Errorf("write egress state: %w", err)
	}
	return nil
}

// errNoState reports that there is nothing recorded to undo — the ordinary
// case on a machine whose last session shut down cleanly.
var errNoState = errors.New("no egress enforcement state recorded")

// readState returns the recorded state, or errNoState when there is nothing to
// undo.
func readState() (*enforcementState, error) {
	raw, err := os.ReadFile(statePath()) //nolint:gosec // a path this package owns
	if os.IsNotExist(err) {
		return nil, errNoState
	}
	if err != nil {
		return nil, fmt.Errorf("read egress state: %w", err)
	}
	var state enforcementState
	if err := json.Unmarshal(raw, &state); err != nil {
		// A corrupt file must not wedge every future start. Report it and let
		// the caller fall back to the documented netsh cleanup.
		return nil, fmt.Errorf("egress state at %s is unreadable: %w", statePath(), err)
	}
	return &state, nil
}

func clearState() error {
	if err := os.Remove(statePath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clear egress state: %w", err)
	}
	return nil
}

// stateDirSDDL builds the DACL for the state directory: full control for
// Administrators, SYSTEM and the account this server runs as, and nothing for
// anyone else.
//
// It is SDDL rather than a hand-built ACL so it can be read in review. "P" makes
// it protected, so ProgramData's inheritable entries — which is where a standard
// user's ability to write here comes from — do not apply. The running user is
// named explicitly because the server may run unelevated in the proxy-only tier
// and still has to write its own state; granting the Users group instead would
// put every other account on the machine back in the same position.
func stateDirSDDL() (string, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("read the current user SID: %w", err)
	}
	return "D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;FA;;;" + user.User.Sid.String() + ")", nil
}

// ensureStateDir creates the state directory with an explicit DACL.
//
// %ProgramData% grants BUILTIN\Users an inheritable right to create
// subdirectories, and CREATOR OWNER full control of what it creates — so a
// standard user who gets there first owns this directory and can write whatever
// they like into egress-rules.json. That file drives an elevated recovery path:
// it names firewall rules to delete, whether to restore the machine's default
// outbound action, and WinINET proxy settings to write into the elevated user's
// registry. Inheriting ProgramData's permissions makes it a local privilege
// escalation, so the directory is created with its own.
//
// If the directory already exists this does not rewrite its DACL: an operator may
// have set one deliberately, and silently replacing it would be its own surprise.
// checkStateDirTrusted is what notices a pre-existing directory that is unsafe.
func ensureStateDir() error {
	dir := stateDir()
	if _, err := os.Stat(dir); err == nil {
		return nil
	}
	sddl, err := stateDirSDDL()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("build egress state directory DACL: %w", err)
	}
	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	pathPtr, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return fmt.Errorf("egress state directory path: %w", err)
	}
	if err := windows.CreateDirectory(pathPtr, sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return fmt.Errorf("create egress state directory %q: %w", dir, err)
	}
	return nil
}
