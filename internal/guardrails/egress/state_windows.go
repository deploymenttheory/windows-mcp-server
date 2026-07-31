//go:build windows && (amd64 || arm64)

package egress

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	if err := os.MkdirAll(stateDir(), 0o755); err != nil {
		return fmt.Errorf("create egress state directory: %w", err)
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode egress state: %w", err)
	}
	// The mode is nominal on Windows — the real access control is the ACL on
	// ProgramData, and Go synthesizes a Unix mode that means nothing here. It is
	// written restrictively anyway so the intent is not misread: this file
	// describes machine state, and only an elevated process should rewrite it.
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
