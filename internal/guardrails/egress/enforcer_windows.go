//go:build windows && (amd64 || arm64)

package egress

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	win32 "github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networkmanagement/windowsfirewall"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/com"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/contain"
)

// clsidNetFwRule is the class identifier of the HNetCfg.FWRule coclass. The
// bindings emit IID_INetFwRule but no CLSIDs at all, so it is declared here —
// the same technique as clsidNetFwPolicy2 in contain/firewall_windows.go and
// clsidCUIAutomation in internal/desktop/uia.go.
var clsidNetFwRule = win32.GUID{
	Data1: 0x2c5bc43e,
	Data2: 0x3369,
	Data3: 0x4c33,
	Data4: [8]byte{0xab, 0x0c, 0xbe, 0x94, 0x69, 0x67, 0x7a, 0xf4},
}

// ruleGroup tags every rule this server creates.
//
// The group is what makes cleanup answerable by a human as well as by us: an
// operator recovering a machine by hand can delete the whole set with
//
//	netsh advfirewall firewall delete rule group="WindowsMCP-Egress"
//
// without needing to know which applications a past session named.
const ruleGroup = "WindowsMCP-Egress"

// ErrNotElevated is returned when firewall enforcement was asked for by a
// process that cannot perform it.
var ErrNotElevated = errors.New("egress enforcement requires an elevated process")

// WindowsEnforcer installs outbound-block firewall rules for the applications
// an operator named, so they cannot reach the network except through the proxy.
//
// The rules are deliberately narrow: they block one image path each and nothing
// else on the machine changes. Windows Firewall does not filter loopback, which
// is what leaves the blocked application able to reach the proxy while every
// other destination is dropped. That property is the whole mechanism.
type WindowsEnforcer struct {
	Logger *slog.Logger
}

// Elevated reports whether this process can change firewall state.
func (WindowsEnforcer) Elevated() bool { return contain.CurrentUserIsAdmin() }

// Apply installs a block rule per application and returns the undo.
//
// Rules are removed by name before being added, so a previous session that died
// without cleaning up does not leave a duplicate or a stale rule shadowing the
// new one. Adding is all-or-nothing: a partial rule set would block some of an
// operator's applications and silently let the rest past, which is worse than
// not starting.
func (e WindowsEnforcer) Apply(spec EnforceSpec) (func() error, error) {
	logger := e.logger()

	// The firewall work and the WinINET work are gated separately. Pointing this
	// user's proxy settings at the listener needs no elevation and is useful on
	// its own, so a proxy-only policy asking for it must not be silently dropped
	// on the way past the firewall early-return — that would leave an operator
	// believing traffic was being routed when nothing had been configured.
	if !specNeedsAction(spec) {
		return func() error { return nil }, nil
	}
	needsFirewall := specNeedsElevation(spec)
	if needsFirewall && !e.Elevated() {
		return nil, ErrNotElevated
	}
	if !needsFirewall {
		return e.applySystemProxyOnly(spec)
	}

	blockNames := ruleNames(spec.Applications)
	allowNames := plannedAllowNames(spec)
	state := enforcementState{
		PID: os.Getpid(), Listen: spec.ProxyAddr, Group: ruleGroup,
		RuleNames: append(append([]string{}, blockNames...), allowNames...),
	}

	// The whole mutation is recorded before any of it happens. A crash between
	// writing and acting leaves a file naming rules that do not exist and
	// default actions that were never changed — both harmless to undo. The
	// reverse order would leave a machine blocked with nothing recording how to
	// unblock it, which is the failure this file exists to prevent.
	if spec.GlobalBlock {
		saved, err := readDefaultOutbound()
		if err != nil {
			return nil, err
		}
		state.SavedOutbound = saved
		state.GlobalBlock = true
	}
	if err := writeState(state); err != nil {
		return nil, err
	}

	if err := contain.WithCOMThread(func() error {
		rules, release, err := openRules()
		if err != nil {
			return err
		}
		defer release()

		// Clear our own names first: Add would otherwise stack a second rule
		// with the same name from a session that did not shut down cleanly.
		for _, name := range state.RuleNames {
			removeRule(rules, name)
		}

		// Allow rules go in BEFORE the default flips. In the other order there
		// is a window — however brief — where the machine has no DNS and no
		// DHCP, and a lease lost in that window does not come back just because
		// the rules arrive afterwards.
		if spec.GlobalBlock {
			if err := addGlobalAllowRules(rules, spec); err != nil {
				removeNamed(rules, state.RuleNames)
				return err
			}
		}
		for i, app := range spec.Applications {
			if err := addBlockRule(rules, blockNames[i], app, spec.ProxyAddr); err != nil {
				// Roll back what this call created, so a failure leaves the
				// machine as it was found rather than half-enforced.
				removeNamed(rules, state.RuleNames)
				return err
			}
		}
		return nil
	}); err != nil {
		_ = clearState() // nothing was installed; do not leave a file claiming otherwise
		return nil, fmt.Errorf("install egress firewall rules: %w", err)
	}

	// Only now, with every exception in place, does the machine become
	// default-deny.
	if spec.GlobalBlock {
		if err := setDefaultOutbound(windowsfirewall.NET_FW_ACTION_BLOCK); err != nil {
			_ = e.removeRules(state.RuleNames)
			_ = clearState()
			return nil, fmt.Errorf("set default outbound to block: %w", err)
		}
		logger.Warn("egress: machine default outbound action is now BLOCK",
			"exceptions", len(allowNames), "recovery_state", statePath())
	}
	if spec.SetSystemProxy {
		savedProxy, err := setSystemProxy(spec.ProxyAddr)
		if err != nil {
			// Unwind the firewall work: a machine pointed at a proxy it cannot
			// use, or blocked with no proxy configured, is worse than either.
			if spec.GlobalBlock {
				_ = restoreDefaultOutbound(state.SavedOutbound)
			}
			_ = e.removeRules(state.RuleNames)
			_ = clearState()
			return nil, fmt.Errorf("point WinINET at the egress proxy: %w", err)
		}
		state.SystemProxy = savedProxy
		// Re-record: the settings to restore were not known until now.
		if err := writeState(state); err != nil {
			_ = restoreSystemProxy(savedProxy)
			if spec.GlobalBlock {
				_ = restoreDefaultOutbound(state.SavedOutbound)
			}
			_ = e.removeRules(state.RuleNames)
			_ = clearState()
			return nil, err
		}
		logger.Info("WinINET proxy settings point at the egress proxy", "addr", spec.ProxyAddr)
	}

	logger.Info("egress enforcement applied",
		"block_rules", len(blockNames), "allow_rules", len(allowNames),
		"global", spec.GlobalBlock, "system_proxy", spec.SetSystemProxy, "group", ruleGroup)

	var undone bool
	restore := func() error {
		if undone {
			return nil
		}
		undone = true
		// Defaults first, rules second — the reverse of how they went on. If
		// the process dies between the two, the machine is already usable and
		// only stale allow rules remain, which the next start clears.
		if spec.GlobalBlock {
			if err := restoreDefaultOutbound(state.SavedOutbound); err != nil {
				return fmt.Errorf("restore default outbound action: %w", err)
			}
		}
		if state.SystemProxy != nil {
			if err := restoreSystemProxy(state.SystemProxy); err != nil {
				return err
			}
		}
		if err := e.removeRules(state.RuleNames); err != nil {
			return err
		}
		logger.Info("egress enforcement removed", "rules", len(state.RuleNames))
		return clearState()
	}
	return restore, nil
}

// applySystemProxyOnly handles the proxy-only tier's WinINET configuration,
// where there is no firewall state to record beyond the settings replaced.
func (e WindowsEnforcer) applySystemProxyOnly(spec EnforceSpec) (func() error, error) {
	saved, err := setSystemProxy(spec.ProxyAddr)
	if err != nil {
		return nil, fmt.Errorf("point WinINET at the egress proxy: %w", err)
	}
	state := enforcementState{
		PID: os.Getpid(), Listen: spec.ProxyAddr, Group: ruleGroup, SystemProxy: saved,
	}
	if err := writeState(state); err != nil {
		_ = restoreSystemProxy(saved)
		return nil, err
	}
	e.logger().Info("WinINET proxy settings point at the egress proxy", "addr", spec.ProxyAddr)

	var undone bool
	return func() error {
		if undone {
			return nil
		}
		undone = true
		if err := restoreSystemProxy(saved); err != nil {
			return err
		}
		return clearState()
	}, nil
}

// Suspend weakens egress without touching the machine's default actions.
//
// It exists for the kill path. When containment isolates the network it flips
// the default outbound action to block — but the allow rules installed for
// global mode beat that default, so svchost and this server's own binary would
// keep their route out during an incident. Disabling those rules closes it.
//
// Restoring is deliberately not done here: undoing anything in Finalize could
// countermand the isolation the kill ladder just applied. Full teardown belongs
// to the exit defer, and a machine that reboots still contained is the correct
// direction to fail.
func (e WindowsEnforcer) Suspend() error {
	state, err := readState()
	if err != nil || state == nil {
		return nil //nolint:nilerr // nothing recorded means nothing to suspend
	}
	if !e.Elevated() {
		return nil
	}
	if err := contain.WithCOMThread(func() error {
		rules, release, err := openRules()
		if err != nil {
			return err
		}
		defer release()
		for _, name := range state.RuleNames {
			if isAllowRuleName(name) {
				_ = setRuleEnabled(rules, name, false)
			}
		}
		e.logger().Warn("egress allow rules disabled for containment", "rules", len(state.RuleNames))
		return nil
	}); err != nil {
		return fmt.Errorf("disable egress allow rules: %w", err)
	}
	return nil
}

func (e WindowsEnforcer) removeRules(names []string) error {
	if err := contain.WithCOMThread(func() error {
		rules, release, err := openRules()
		if err != nil {
			return err
		}
		defer release()
		removeNamed(rules, names)
		return nil
	}); err != nil {
		return fmt.Errorf("remove egress firewall rules: %w", err)
	}
	return nil
}

func removeNamed(rules *windowsfirewall.INetFwRules, names []string) {
	for _, name := range names {
		removeRule(rules, name)
	}
}

// plannedAllowNames is the allow-rule set global mode will create. Naming them
// up front is what lets the state file record the whole mutation before any of
// it happens.
func plannedAllowNames(spec EnforceSpec) []string {
	if !spec.GlobalBlock {
		return nil
	}
	names := []string{proxyAllowRuleName()}
	for _, ex := range defaultExceptions() {
		names = append(names, exceptionRuleName(ex))
	}
	return names
}

func isAllowRuleName(name string) bool {
	return strings.HasPrefix(name, ruleGroup+"-Allow-")
}

// isOwnRuleName reports whether a rule name is one this package could have
// created. Recovery removes only these.
//
// The state file lives in %ProgramData%\WindowsMCP, which a standard user can
// create and therefore own, and nothing validates its contents. Without this
// check, planting a file naming "Core Networking - DNS (UDP-Out)" or an EDR
// agent's rule made the next elevated start delete it -- the recovery path
// turned into an arbitrary-firewall-rule remover running with the operator's
// privileges. Recovery is meant to undo this package's own work; a name outside
// its namespace is not that.
func isOwnRuleName(name string) bool {
	return strings.HasPrefix(name, ruleGroup+"-")
}

// addGlobalAllowRules installs the proxy's own route out plus the exception set
// that keeps the machine functioning under a block-by-default policy.
func addGlobalAllowRules(rules *windowsfirewall.INetFwRules, spec EnforceSpec) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate this executable for the proxy allow rule: %w", err)
	}
	if err := addProxyAllowRule(rules, exe, proxyAllowPorts(spec)); err != nil {
		return err
	}
	for _, ex := range defaultExceptions() {
		if err := addExceptionRule(rules, ex); err != nil {
			return err
		}
	}
	return nil
}

// proxyAllowPorts bounds where the proxy itself may reach. It mirrors the
// policy's allow_ports, so the firewall rule is no broader than the allowlist
// the proxy already enforces.
func proxyAllowPorts(spec EnforceSpec) string {
	if len(spec.AllowPorts) == 0 {
		return "80,443"
	}
	parts := make([]string, 0, len(spec.AllowPorts))
	for _, p := range spec.AllowPorts {
		parts = append(parts, strconv.Itoa(p))
	}
	return strings.Join(parts, ",")
}

// Recover removes any rules left behind by a session that did not shut down.
//
// It runs on every startup, including when the current policy disables egress:
// rules from an earlier run are exactly what nothing else would clean up, and a
// machine left with a blocked browser and no server to explain it is the worst
// failure this package can produce.
//
// The names cannot be re-derived — they come from an application list this run
// may no longer have — so recovery reads the state file written before the
// rules were created.
func (e WindowsEnforcer) Recover() (int, error) {
	state, err := readState()
	switch {
	case errors.Is(err, errNoState):
		return 0, nil
	case err != nil:
		// A corrupt state file must not wedge every future start; say so and
		// point at the manual cleanup rather than refusing to run.
		e.logger().Error("egress recovery state is unreadable; clean up by hand",
			"error", err,
			"command", `netsh advfirewall firewall delete rule group="`+ruleGroup+`"`)
		return 0, nil
	case len(state.RuleNames) == 0:
		return 0, clearState()
	}
	if !e.Elevated() {
		// The rules are real and this process cannot remove them. Silence would
		// leave an operator with a blocked application and no explanation, so
		// this case says so on every start until it is resolved.
		e.logger().Error("egress firewall rules from a previous session are still installed, "+
			"and this process is not elevated to remove them",
			"rules", len(state.RuleNames), "previous_pid", state.PID,
			"fix", `run elevated, or: netsh advfirewall firewall delete rule group="`+ruleGroup+`"`)
		return 0, nil
	}

	// The machine's default action comes back first and unconditionally. Stale
	// rules are an untidiness; a machine left default-deny with nothing running
	// to proxy it has no working network, and that is what a user would
	// experience as the computer being broken.
	if state.GlobalBlock {
		if err := restoreDefaultOutbound(state.SavedOutbound); err != nil {
			e.logger().Error("could not restore the machine's default outbound action; "+
				"the network will stay blocked until this is fixed",
				"error", err,
				"fix", "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound")
			return 0, err
		}
		e.logger().Warn("restored the machine's default outbound action after an unclean shutdown",
			"previous_pid", state.PID)
	}
	if state.SystemProxy != nil {
		if err := restoreSystemProxy(state.SystemProxy); err != nil {
			e.logger().Error("could not restore WinINET proxy settings", "error", err)
		}
	}

	var removed int
	if err := contain.WithCOMThread(func() error {
		rules, release, err := openRules()
		if err != nil {
			return err
		}
		defer release()
		for _, name := range state.RuleNames {
			if !isOwnRuleName(name) {
				// Not ours to remove. Recorded rather than ignored: a name outside
				// the namespace means the state file was written by something other
				// than a previous run of this package.
				e.logger().Error("refusing to remove a firewall rule named in the egress "+
					"recovery state but outside this server's namespace; the state file "+
					"may have been tampered with",
					"rule", name, "expected_prefix", ruleGroup+"-", "state_file", statePath())
				continue
			}
			if ruleExists(rules, name) {
				removeRule(rules, name)
				removed++
			}
		}
		return nil
	}); err != nil {
		return removed, fmt.Errorf("remove egress firewall rules from a previous session: %w", err)
	}
	if removed > 0 {
		e.logger().Warn("removed egress firewall rules left by a previous session",
			"rules", removed, "group", ruleGroup, "previous_pid", state.PID)
	}
	return removed, clearState()
}

func (e WindowsEnforcer) logger() *slog.Logger {
	if e.Logger != nil {
		return e.Logger
	}
	return slog.Default()
}

var errNotSupported = errors.New("egress enforcement mode not supported")

// ruleNames derives a deterministic rule name per application, so a rule can be
// found and removed later without keeping state on disk. The index keeps two
// applications with the same basename distinct.
func ruleNames(apps []string) []string {
	names := make([]string, len(apps))
	for i, app := range apps {
		base := strings.TrimSuffix(filepath.Base(app), filepath.Ext(app))
		names[i] = fmt.Sprintf("%s-Block-%s-%d", ruleGroup, base, i)
	}
	return names
}

// openRules returns the firewall rule collection. Must run on a COM-initialized
// thread (contain.WithCOMThread).
func openRules() (*windowsfirewall.INetFwRules, func(), error) {
	policy, releasePolicy, err := contain.NewFwPolicy()
	if err != nil {
		return nil, nil, fmt.Errorf("open firewall policy: %w", err)
	}
	rules, err := policy.Get_Rules()
	if err != nil {
		releasePolicy()
		return nil, nil, fmt.Errorf("read firewall rules: %w", err)
	}
	release := func() {
		rules.Release()
		releasePolicy()
	}
	return rules, release, nil
}

// addBlockRule creates one outbound-block rule for an image path.
//
// Protocol is ANY rather than TCP on purpose: QUIC is UDP, and a TCP-only rule
// would leave HTTP/3 as an open path straight past the proxy. Ports are left
// unset because Windows rejects a port on a rule whose protocol is ANY.
func addBlockRule(rules *windowsfirewall.INetFwRules, name, appPath, proxyAddr string) error {
	rule, release, err := newRuleObject()
	if err != nil {
		return err
	}
	defer release()

	description := fmt.Sprintf(
		"Blocked by windows-mcp-server egress policy. Reach approved destinations through the proxy at %s.",
		proxyAddr)

	set := []struct {
		what string
		err  error
	}{
		{"name", withBSTR(name, rule.Put_Name)},
		{"description", withBSTR(description, rule.Put_Description)},
		{"application", withBSTR(appPath, rule.Put_ApplicationName)},
		{"grouping", withBSTR(ruleGroup, rule.Put_Grouping)},
		{"protocol", rule.Put_Protocol(int32(windowsfirewall.NET_FW_IP_PROTOCOL_ANY))},
		{"direction", rule.Put_Direction(windowsfirewall.NET_FW_RULE_DIR_OUT)},
		{"action", rule.Put_Action(windowsfirewall.NET_FW_ACTION_BLOCK)},
		{"profiles", rule.Put_Profiles(int32(windowsfirewall.NET_FW_PROFILE2_ALL))},
		{"enabled", rule.Put_Enabled(foundation.VARIANT_TRUE)},
	}
	for _, step := range set {
		if step.err != nil {
			return fmt.Errorf("set rule %s for %q: %w", step.what, appPath, step.err)
		}
	}
	if err := rules.Add(rule); err != nil {
		return fmt.Errorf("add firewall rule %q: %w", name, err)
	}
	return nil
}

// newRuleObject instantiates an empty INetFwRule. Must run on a COM-initialized
// thread; the returned func releases it.
func newRuleObject() (*windowsfirewall.INetFwRule, func(), error) {
	var unk *win32.IUnknown
	if err := com.CoCreateInstance(
		&clsidNetFwRule,
		nil,
		com.CLSCTX_INPROC_SERVER,
		&windowsfirewall.IID_INetFwRule,
		&unk,
	); err != nil {
		return nil, nil, fmt.Errorf("CoCreateInstance(NetFwRule): %w", err)
	}
	if unk == nil {
		return nil, nil, errNilRuleInterface
	}
	rule := (*windowsfirewall.INetFwRule)(unsafe.Pointer(unk))
	return rule, func() { rule.Release() }, nil
}

var errNilRuleInterface = errors.New("CoCreateInstance(NetFwRule) returned a nil interface")

// withBSTR allocates a BSTR, hands it to a setter and frees it. Every string
// property crosses the COM boundary this way, and forgetting the free is a leak
// that only shows up under a long-running session.
func withBSTR(value string, set func(foundation.BSTR) error) error {
	b := foundation.SysAllocString(value)
	defer foundation.SysFreeString(b)
	return set(b)
}

// removeRule deletes a rule by name, ignoring "not found".
//
// Cleanup is best-effort by design: it runs on shutdown paths, including after
// a kill, where refusing to continue because one rule had already gone would
// leave the rest of them installed.
func removeRule(rules *windowsfirewall.INetFwRules, name string) {
	b := foundation.SysAllocString(name)
	defer foundation.SysFreeString(b)
	_ = rules.Remove(b)
}

// ruleExists reports whether a rule of that name is present, so recovery only
// reports what it actually removed.
func ruleExists(rules *windowsfirewall.INetFwRules, name string) bool {
	b := foundation.SysAllocString(name)
	defer foundation.SysFreeString(b)
	rule, err := rules.Item(b)
	if err != nil || rule == nil {
		return false
	}
	rule.Release()
	return true
}
