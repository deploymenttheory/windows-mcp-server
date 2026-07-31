//go:build windows && (amd64 || arm64)

package egress

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/contain"
)

// These tests are the only ones that install real Windows Firewall rules, which
// is the one step the unprivileged suite cannot reach: INetFwRules.Add is the
// sole call in this package that needs elevation.
//
// They are gated twice on purpose. Elevation alone is not enough of a signal —
// GitHub's Windows runners are elevated, and a test that silently mutates the
// firewall of any machine that happens to run it is the wrong default for a
// security control. So an operator must also opt in explicitly:
//
//	set WINDOWS_MCP_FIREWALL_TEST=1
//	go test ./internal/guardrails/egress/ -run TestElevated -v -count=1
//
// Everything is scoped to be harmless even if it fails badly:
//
//   - The rules name an executable that does not exist, so a rule surviving
//     cleanup blocks nothing real.
//   - The recovery state file is redirected into the test's temp directory, so
//     the machine's real state at %ProgramData% is never touched.
//   - Cleanup is registered before anything is created and removes the rules by
//     name regardless of how the test exits.
const firewallTestEnv = "WINDOWS_MCP_FIREWALL_TEST"

// selfTestApp is deliberately a path with no file behind it. Windows Firewall
// stores the string without checking, so the rule is real while blocking a
// program that cannot exist.
const selfTestApp = `C:\Windows\System32\windows-mcp-egress-selftest-does-not-exist.exe`

// optedIn reads the gate tolerantly. `set VAR=1 && go test` in cmd.exe assigns
// "1 " — everything between the = and the && , trailing space included — so an
// exact comparison silently skips the very run an operator just asked for. The
// spellings accepted here match the coercion the tool layer already does in
// pkg/windows/params.go.
func optedIn() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(firewallTestEnv))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func requireElevatedOptIn(t *testing.T) WindowsEnforcer {
	t.Helper()
	if !optedIn() {
		t.Skipf("set %s=1 to run the tests that install real firewall rules", firewallTestEnv)
	}
	e := WindowsEnforcer{}
	if !e.Elevated() {
		t.Fatalf("%s=1 was set but this process is not elevated; run from an elevated prompt", firewallTestEnv)
	}
	return e
}

// removeSelfTestRules is the belt-and-braces cleanup: it removes by name,
// whatever happened, so a failed assertion cannot leave rules behind.
func removeSelfTestRules(t *testing.T, names []string) {
	t.Helper()
	err := contain.WithCOMThread(func() error {
		rules, release, err := openRules()
		if err != nil {
			return err
		}
		defer release()
		for _, name := range names {
			removeRule(rules, name)
		}
		return nil
	})
	if err != nil {
		t.Errorf("cleanup could not reach the firewall; remove by hand: "+
			`netsh advfirewall firewall delete rule group="%s" (%v)`, ruleGroup, err)
	}
}

func selfTestRulesPresent(t *testing.T, names []string) []bool {
	t.Helper()
	present := make([]bool, len(names))
	if err := contain.WithCOMThread(func() error {
		rules, release, err := openRules()
		if err != nil {
			return err
		}
		defer release()
		for i, name := range names {
			present[i] = ruleExists(rules, name)
		}
		return nil
	}); err != nil {
		t.Fatalf("could not read the firewall: %v", err)
	}
	return present
}

// TestElevatedApplyInstallsAndRemovesRules is the end-to-end proof that
// Rules.Add works with these bindings and that teardown is complete.
func TestElevatedApplyInstallsAndRemovesRules(t *testing.T) {
	e := requireElevatedOptIn(t)
	t.Setenv("ProgramData", t.TempDir()) // isolate the recovery state file

	apps := []string{selfTestApp}
	names := ruleNames(apps)
	t.Cleanup(func() { removeSelfTestRules(t, names) })

	restore, err := e.Apply(EnforceSpec{ProxyAddr: "127.0.0.1:8181", Applications: apps})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	for i, present := range selfTestRulesPresent(t, names) {
		if !present {
			t.Errorf("rule %q was not installed", names[i])
		}
	}
	t.Logf("installed: %v", names)

	// The state file must name exactly what was created, so a crash here is
	// recoverable by the next start.
	state, err := readState()
	if err != nil {
		t.Fatalf("recovery state after Apply: %v", err)
	}
	if len(state.RuleNames) != len(names) || state.RuleNames[0] != names[0] {
		t.Errorf("state records %v, want %v", state.RuleNames, names)
	}
	if state.PID != os.Getpid() {
		t.Errorf("state records pid %d, want %d", state.PID, os.Getpid())
	}

	if err := restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	for i, present := range selfTestRulesPresent(t, names) {
		if present {
			t.Errorf("rule %q survived restore", names[i])
		}
	}
	if _, err := readState(); !errors.Is(err, errNoState) {
		t.Errorf("restore left recovery state behind: %v", err)
	}

	// Restoring twice must be safe: the normal-exit defer and the kill path
	// both reach it.
	if err := restore(); err != nil {
		t.Errorf("second restore should be a no-op: %v", err)
	}
	t.Log("rules removed and state cleared")
}

// TestElevatedRecoverCleansUpAfterACrash simulates the case the state file
// exists for: rules installed, process gone without running its teardown.
func TestElevatedRecoverCleansUpAfterACrash(t *testing.T) {
	e := requireElevatedOptIn(t)
	t.Setenv("ProgramData", t.TempDir())

	apps := []string{selfTestApp}
	names := ruleNames(apps)
	t.Cleanup(func() { removeSelfTestRules(t, names) })

	// Install, then deliberately drop the restore func on the floor — this is
	// what a Stop-Process or a power cut leaves behind.
	if _, err := e.Apply(EnforceSpec{ProxyAddr: "127.0.0.1:8181", Applications: apps}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for i, present := range selfTestRulesPresent(t, names) {
		if !present {
			t.Fatalf("rule %q was not installed, so the recovery case cannot be tested", names[i])
		}
	}

	removed, err := e.Recover()
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if removed != len(names) {
		t.Errorf("Recover removed %d rules, want %d", removed, len(names))
	}
	for i, present := range selfTestRulesPresent(t, names) {
		if present {
			t.Errorf("rule %q survived Recover", names[i])
		}
	}
	if _, err := readState(); !errors.Is(err, errNoState) {
		t.Errorf("Recover left the state file behind: %v", err)
	}

	// A second Recover has nothing to do and must not error.
	if n, err := e.Recover(); n != 0 || err != nil {
		t.Errorf("second Recover = (%d, %v), want (0, nil)", n, err)
	}
	t.Log("crash recovery removed the rules and cleared the state")
}

// TestElevatedApplyIsIdempotent covers a restart that finds its own rules still
// installed: Apply clears its names first, so it must not stack duplicates or
// fail.
func TestElevatedApplyIsIdempotent(t *testing.T) {
	e := requireElevatedOptIn(t)
	t.Setenv("ProgramData", t.TempDir())

	apps := []string{selfTestApp}
	names := ruleNames(apps)
	t.Cleanup(func() { removeSelfTestRules(t, names) })

	first, err := e.Apply(EnforceSpec{ProxyAddr: "127.0.0.1:8181", Applications: apps})
	if err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	second, err := e.Apply(EnforceSpec{ProxyAddr: "127.0.0.1:8181", Applications: apps})
	if err != nil {
		t.Fatalf("second Apply over existing rules: %v", err)
	}

	// One removal must leave nothing behind; if Apply had stacked a duplicate,
	// a rule of this name would still be present.
	if err := second(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	for i, present := range selfTestRulesPresent(t, names) {
		if present {
			t.Errorf("rule %q survived removal, so Apply stacked a duplicate", names[i])
		}
	}
	_ = first
	t.Log("re-applying over existing rules left exactly one rule per application")
}
