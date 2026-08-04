//go:build windows && (amd64 || arm64)

package egress

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	win32 "github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networkmanagement/windowsfirewall"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/com"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/contain"
)

// TestRuleNamesAreDeterministicAndDistinct is what makes cleanup possible: the
// same application list must produce the same names on a later run, and two
// applications sharing a basename must not collide onto one rule.
func TestRuleNamesAreDeterministicAndDistinct(t *testing.T) {
	apps := []string{
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Vendor\chrome.exe`,
		`C:\Windows\System32\curl.exe`,
	}
	first := ruleNames(apps)
	second := ruleNames(apps)

	if len(first) != len(apps) {
		t.Fatalf("got %d names for %d applications", len(first), len(apps))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Errorf("name %d is not stable: %q then %q", i, first[i], second[i])
		}
		if !strings.HasPrefix(first[i], ruleGroup) {
			t.Errorf("name %q should carry the group prefix so manual cleanup can find it", first[i])
		}
	}
	// The two chrome.exe entries must be separate rules.
	if first[0] == first[1] {
		t.Errorf("applications sharing a basename collided onto one rule name: %q", first[0])
	}
	if !strings.Contains(first[0], "chrome") || !strings.Contains(first[2], "curl") {
		t.Errorf("names should identify the application: %v", first)
	}
}

// TestEnforcementStateRoundTrips covers the file recovery depends on. It is
// written before any rule exists, so a crash between the two leaves a file
// naming rules that were never created — which must read back cleanly.
func TestEnforcementStateRoundTrips(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())

	if state, err := readState(); state != nil || !errors.Is(err, errNoState) {
		t.Fatalf("a fresh machine reports errNoState, got (%v, %v)", state, err)
	}

	want := enforcementState{
		PID: 4321, Listen: "127.0.0.1:8181", Group: ruleGroup,
		RuleNames: []string{ruleGroup + "-Block-chrome-0"},
	}
	if err := writeState(want); err != nil {
		t.Fatal(err)
	}
	got, err := readState()
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.PID != want.PID || got.Listen != want.Listen ||
		len(got.RuleNames) != 1 || got.RuleNames[0] != want.RuleNames[0] {
		t.Errorf("state round-trip lost data: %+v", got)
	}

	if err := clearState(); err != nil {
		t.Fatal(err)
	}
	if _, err := readState(); !errors.Is(err, errNoState) {
		t.Errorf("clearState left the file behind: %v", err)
	}
	// Clearing twice must be safe: teardown paths can overlap.
	if err := clearState(); err != nil {
		t.Errorf("clearState is not idempotent: %v", err)
	}
}

// TestCorruptStateIsReportedNotFatal keeps a bad file from wedging every future
// start — the server must come up and tell the operator how to clean up.
func TestCorruptStateIsReportedNotFatal(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ProgramData", dir)
	if err := os.MkdirAll(filepath.Join(dir, stateDirName), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := readState(); err == nil {
		t.Error("a corrupt state file should be reported as an error")
	}
	// Recover swallows it deliberately: refusing to start would be worse.
	var e WindowsEnforcer
	removed, err := e.Recover()
	if err != nil || removed != 0 {
		t.Errorf("Recover over a corrupt file = (%d, %v), want (0, nil)", removed, err)
	}
}

// TestRecoverWithNoStateDoesNothing is the ordinary case on a clean machine.
func TestRecoverWithNoStateDoesNothing(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	var e WindowsEnforcer
	removed, err := e.Recover()
	if removed != 0 || err != nil {
		t.Errorf("Recover on a clean machine = (%d, %v), want (0, nil)", removed, err)
	}
}

// TestFirewallRuleObjectAcceptsEveryProperty exercises the COM path that the
// unit tests otherwise cannot reach: the hand-declared HNetCfg.FWRule CLSID,
// and every Put_* call with the exact argument types the bindings expect.
//
// It stops short of Rules.Add, which is the only step needing elevation, so it
// runs on an ordinary developer machine and in CI while still catching a wrong
// CLSID, a wrong IID, or a property the bindings type differently than assumed
// — the failures that would otherwise surface only on an elevated machine.
//
// It self-skips where COM cannot be initialised, as the desktop tests do.
func TestFirewallRuleObjectAcceptsEveryProperty(t *testing.T) {
	err := contain.WithCOMThread(func() error {
		var unk *win32.IUnknown
		if err := com.CoCreateInstance(
			&clsidNetFwRule, nil, com.CLSCTX_INPROC_SERVER,
			&windowsfirewall.IID_INetFwRule, &unk,
		); err != nil {
			return err
		}
		if unk == nil {
			t.Fatal("CoCreateInstance returned a nil interface for the FWRule CLSID")
		}
		rule := (*windowsfirewall.INetFwRule)(unsafe.Pointer(unk))
		defer rule.Release()

		if err := withBSTR(ruleGroup+"-Block-selftest-0", rule.Put_Name); err != nil {
			t.Errorf("Put_Name: %v", err)
		}
		if err := withBSTR("self-test, never added", rule.Put_Description); err != nil {
			t.Errorf("Put_Description: %v", err)
		}
		if err := withBSTR(`C:\Windows\System32\curl.exe`, rule.Put_ApplicationName); err != nil {
			t.Errorf("Put_ApplicationName: %v", err)
		}
		if err := withBSTR(ruleGroup, rule.Put_Grouping); err != nil {
			t.Errorf("Put_Grouping: %v", err)
		}
		// Protocol ANY is the choice that also covers QUIC over UDP; Windows
		// rejects a port on such a rule, which is why none is set.
		if err := rule.Put_Protocol(int32(windowsfirewall.NET_FW_IP_PROTOCOL_ANY)); err != nil {
			t.Errorf("Put_Protocol: %v", err)
		}
		if err := rule.Put_Direction(windowsfirewall.NET_FW_RULE_DIR_OUT); err != nil {
			t.Errorf("Put_Direction: %v", err)
		}
		if err := rule.Put_Action(windowsfirewall.NET_FW_ACTION_BLOCK); err != nil {
			t.Errorf("Put_Action: %v", err)
		}
		if err := rule.Put_Profiles(int32(windowsfirewall.NET_FW_PROFILE2_ALL)); err != nil {
			t.Errorf("Put_Profiles: %v", err)
		}
		if err := rule.Put_Enabled(foundation.VARIANT_TRUE); err != nil {
			t.Errorf("Put_Enabled: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Skipf("cannot instantiate the firewall rule object here: %v", err)
	}
}

// TestFirewallRulesCollectionIsReachable checks the read path to the rule
// store, which also needs no elevation. If this works and Apply still fails,
// the cause is elevation rather than a binding mistake.
func TestFirewallRulesCollectionIsReachable(t *testing.T) {
	err := contain.WithCOMThread(func() error {
		rules, release, err := openRules()
		if err != nil {
			return err
		}
		defer release()
		count, err := rules.Get_Count()
		if err != nil {
			return err
		}
		if count < 0 {
			t.Errorf("negative rule count %d", count)
		}
		t.Logf("firewall reports %d rules", count)
		// A rule we never created must not be found.
		if ruleExists(rules, ruleGroup+"-Block-nonexistent-999") {
			t.Error("a rule this server never created was reported present")
		}
		return nil
	})
	if err != nil {
		t.Skipf("cannot reach the firewall rule store here: %v", err)
	}
}

// TestGlobalBlockRefusesWithoutElevation: flipping the machine's default
// outbound action is the most disruptive thing this package does, so an
// unprivileged process must be turned away before it touches anything.
func TestGlobalBlockRefusesWithoutElevation(t *testing.T) {
	var e WindowsEnforcer
	if e.Elevated() {
		t.Skip("test host is elevated; the refusal path cannot be exercised here")
	}
	_, err := e.Apply(EnforceSpec{GlobalBlock: true, ProxyAddr: "127.0.0.1:8181", AllowPorts: []int{443}})
	if !errors.Is(err, ErrNotElevated) {
		t.Errorf("global block without elevation = %v, want ErrNotElevated", err)
	}
}

// TestGlobalAllowRulesCoverTheMachineEssentials pins the exception set. Each of
// these is a Windows component whose loss makes a default-deny machine look
// broken rather than governed, so a future edit that drops one should have to
// say so here.
func TestGlobalAllowRulesCoverTheMachineEssentials(t *testing.T) {
	names := plannedAllowNames(EnforceSpec{GlobalBlock: true})
	joined := strings.Join(names, " ")
	for _, essential := range []string{
		"Allow-Proxy",   // this server's own route out
		"Allow-DNS-UDP", // without it nothing resolves
		"Allow-DNS-TCP",
		"Allow-DHCP", // without it the machine loses its lease entirely
		"Allow-NTP",
		"Allow-NCSI", // without it Windows reports no internet and apps stop trying
		"Allow-WindowsUpdate",
		"Allow-CryptSvc", // without it signature checks hang rather than fail
	} {
		if !strings.Contains(joined, essential) {
			t.Errorf("the global exception set is missing %s: %v", essential, names)
		}
	}
	// Every name must be recognisable as an allow rule, because Suspend picks
	// them out by prefix to disable during containment.
	for _, name := range names {
		if !isAllowRuleName(name) {
			t.Errorf("%q is not recognised as an allow rule, so containment would not disable it", name)
		}
	}
	// Scoped mode creates none of them.
	if got := plannedAllowNames(EnforceSpec{Applications: []string{`C:\a.exe`}}); len(got) != 0 {
		t.Errorf("scoped mode should plan no allow rules, got %v", got)
	}
}

// TestProxyAllowPortsMirrorsThePolicy keeps the firewall grant no broader than
// the allowlist the proxy itself enforces.
func TestProxyAllowPortsMirrorsThePolicy(t *testing.T) {
	if got := proxyAllowPorts(EnforceSpec{AllowPorts: []int{443}}); got != "443" {
		t.Errorf("ports = %q, want 443", got)
	}
	if got := proxyAllowPorts(EnforceSpec{AllowPorts: []int{443, 80}}); got != "443,80" {
		t.Errorf("ports = %q, want 443,80", got)
	}
	if got := proxyAllowPorts(EnforceSpec{}); got != "80,443" {
		t.Errorf("default ports = %q, want 80,443", got)
	}
}

// TestRecoverOnlyRemovesItsOwnRules is a regression test for a local privilege
// escalation. The state file lives in %ProgramData%\WindowsMCP, which a standard
// user can create and therefore own, and its contents were trusted verbatim by an
// elevated recovery path. Planting a file naming "Core Networking - DNS (UDP-Out)"
// or an EDR agent's rule made the next elevated start delete it.
func TestRecoverOnlyRemovesItsOwnRules(t *testing.T) {
	ours := []string{
		ruleGroup + "-Allow-proxy",
		ruleGroup + "-Block-chrome",
	}
	theirs := []string{
		"Core Networking - DNS (UDP-Out)",
		"CrowdStrike Falcon Sensor",
		"",
		"windowsmcp-egress-lowercase", // prefix match is exact, not case-folded
		ruleGroup, // the bare group name is not a rule this package creates
	}
	for _, name := range ours {
		if !isOwnRuleName(name) {
			t.Errorf("isOwnRuleName(%q) = false; recovery must still clean up its own rules", name)
		}
	}
	for _, name := range theirs {
		if isOwnRuleName(name) {
			t.Errorf("isOwnRuleName(%q) = true; a tampered state file must not be able to "+
				"name an unrelated firewall rule for elevated deletion", name)
		}
	}
}
