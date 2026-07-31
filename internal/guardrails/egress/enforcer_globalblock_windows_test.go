//go:build windows && (amd64 || arm64)

package egress

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networkmanagement/windowsfirewall"
)

// These are the most disruptive tests in the repository: they flip the
// machine's default outbound action to block. Between Apply and restore the
// host is default-deny, and a process killed in that window leaves it that way
// until the next start recovers it or an operator runs the documented netsh
// command.
//
// They therefore have their own opt-in, deliberately NOT the one the scoped
// firewall tests use. Someone running those must never cut their machine off by
// accident:
//
//	set WINDOWS_MCP_GLOBAL_BLOCK_TEST=1
//	go test ./internal/guardrails/egress/ -run TestGlobalBlockLive -v -count=1
//
// Run them in a VM or a machine you can afford to lose the network on.
const globalBlockTestEnv = "WINDOWS_MCP_GLOBAL_BLOCK_TEST"

func requireGlobalBlockOptIn(t *testing.T) WindowsEnforcer {
	t.Helper()
	if strings.ToLower(strings.TrimSpace(os.Getenv(globalBlockTestEnv))) != "1" {
		t.Skipf("set %s=1 to run the tests that make this machine default-deny", globalBlockTestEnv)
	}
	e := WindowsEnforcer{}
	if !e.Elevated() {
		t.Fatalf("%s=1 was set but this process is not elevated", globalBlockTestEnv)
	}
	return e
}

// currentOutbound reads the live default outbound action per profile, so the
// test asserts on the machine rather than on its own bookkeeping.
func currentOutbound(t *testing.T) map[int32]int32 {
	t.Helper()
	saved, err := readDefaultOutbound()
	if err != nil {
		t.Fatalf("read default outbound action: %v", err)
	}
	out := map[int32]int32{}
	for _, s := range saved {
		out[s.Profile] = s.Action
	}
	return out
}

// TestGlobalBlockLiveAppliesAndRestores is the end-to-end proof for the
// disruptive path: the machine really becomes default-deny, the exception rules
// really exist, and restoring really puts the prior actions back.
func TestGlobalBlockLiveAppliesAndRestores(t *testing.T) {
	e := requireGlobalBlockOptIn(t)
	t.Setenv("ProgramData", t.TempDir())

	before := currentOutbound(t)
	t.Logf("default outbound before: %v", before)

	spec := EnforceSpec{ProxyAddr: "127.0.0.1:8181", GlobalBlock: true, AllowPorts: []int{443}}
	names := plannedAllowNames(spec)

	// Registered before Apply so the machine is put back however this exits —
	// including a panic. Restoring the default action matters far more than
	// removing the rules: rules are untidiness, a blocked default is a machine
	// with no network.
	t.Cleanup(func() {
		saved := make([]savedOutbound, 0, len(before))
		for profile, action := range before {
			saved = append(saved, savedOutbound{Profile: profile, Action: action})
		}
		if err := restoreDefaultOutbound(saved); err != nil {
			t.Errorf("EMERGENCY: could not restore the default outbound action. Run: "+
				"netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound (%v)", err)
		}
		removeSelfTestRules(t, names)
	})

	restore, err := e.Apply(spec)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	during := currentOutbound(t)
	for profile, action := range during {
		if action != int32(windowsfirewall.NET_FW_ACTION_BLOCK) {
			t.Errorf("profile %d default outbound = %d, want BLOCK", profile, action)
		}
	}
	for i, present := range selfTestRulesPresent(t, names) {
		if !present {
			t.Errorf("exception rule %q was not installed; a real run would have broken the machine", names[i])
		}
	}
	t.Logf("machine is default-deny with %d exception rules", len(names))

	if err := restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	after := currentOutbound(t)
	for profile, want := range before {
		if after[profile] != want {
			t.Errorf("profile %d default outbound = %d after restore, want %d", profile, after[profile], want)
		}
	}
	for i, present := range selfTestRulesPresent(t, names) {
		if present {
			t.Errorf("exception rule %q survived restore", names[i])
		}
	}
	if _, err := readState(); !errors.Is(err, errNoState) {
		t.Errorf("restore left recovery state behind: %v", err)
	}
	t.Log("default outbound action and rules restored")
}

// TestGlobalBlockLiveRecoversAfterACrash is the scenario the state file exists
// for, and the one that decides whether a crash costs an operator their
// network: the machine is left default-deny with the process gone.
func TestGlobalBlockLiveRecoversAfterACrash(t *testing.T) {
	e := requireGlobalBlockOptIn(t)
	t.Setenv("ProgramData", t.TempDir())

	before := currentOutbound(t)
	spec := EnforceSpec{ProxyAddr: "127.0.0.1:8181", GlobalBlock: true, AllowPorts: []int{443}}
	names := plannedAllowNames(spec)

	t.Cleanup(func() {
		saved := make([]savedOutbound, 0, len(before))
		for profile, action := range before {
			saved = append(saved, savedOutbound{Profile: profile, Action: action})
		}
		if err := restoreDefaultOutbound(saved); err != nil {
			t.Errorf("EMERGENCY: could not restore the default outbound action. Run: "+
				"netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound (%v)", err)
		}
		removeSelfTestRules(t, names)
	})

	// Apply, then drop the restore func — this is a Stop-Process or a power cut.
	if _, err := e.Apply(spec); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for profile, action := range currentOutbound(t) {
		if action != int32(windowsfirewall.NET_FW_ACTION_BLOCK) {
			t.Fatalf("profile %d is not blocked, so the recovery case cannot be tested", profile)
		}
	}

	if _, err := e.Recover(); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	after := currentOutbound(t)
	for profile, want := range before {
		if after[profile] != want {
			t.Errorf("profile %d default outbound = %d after Recover, want %d", profile, after[profile], want)
		}
	}
	if _, err := readState(); !errors.Is(err, errNoState) {
		t.Errorf("Recover left the state file behind: %v", err)
	}
	t.Log("crash recovery restored the machine's default outbound action")
}

// TestGlobalBlockLiveSuspendDisablesAllowRules covers the kill path: the allow
// rules beat a blocked default, so containment has to switch them off or this
// server and the exempted services keep their route out during an incident.
func TestGlobalBlockLiveSuspendDisablesAllowRules(t *testing.T) {
	e := requireGlobalBlockOptIn(t)
	t.Setenv("ProgramData", t.TempDir())

	before := currentOutbound(t)
	spec := EnforceSpec{ProxyAddr: "127.0.0.1:8181", GlobalBlock: true, AllowPorts: []int{443}}
	names := plannedAllowNames(spec)

	restore, err := e.Apply(spec)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	t.Cleanup(func() {
		_ = restore()
		saved := make([]savedOutbound, 0, len(before))
		for profile, action := range before {
			saved = append(saved, savedOutbound{Profile: profile, Action: action})
		}
		_ = restoreDefaultOutbound(saved)
		removeSelfTestRules(t, names)
	})

	if err := e.Suspend(); err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	// Suspend must not restore the default action — that would countermand the
	// containment the kill ladder just applied.
	for profile, action := range currentOutbound(t) {
		if action != int32(windowsfirewall.NET_FW_ACTION_BLOCK) {
			t.Errorf("profile %d was un-blocked by Suspend; containment must not be undone there", profile)
		}
	}
	// The rules still exist, but disabled.
	for i, present := range selfTestRulesPresent(t, names) {
		if !present {
			t.Errorf("Suspend removed rule %q; it should only disable them", names[i])
		}
	}
	t.Log("Suspend disabled the allow rules while leaving containment in force")
}
