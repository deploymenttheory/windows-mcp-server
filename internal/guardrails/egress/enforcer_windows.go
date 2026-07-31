//go:build windows && (amd64 || arm64)

package egress

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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
	if spec.GlobalBlock {
		// Phase 3. Refusing is the honest answer: accepting the flag and doing
		// nothing would leave an operator believing the machine is default-deny.
		return nil, fmt.Errorf("%w: egress.block_all_outbound is not implemented yet", errNotSupported)
	}
	if len(spec.Applications) == 0 {
		return func() error { return nil }, nil
	}
	if !e.Elevated() {
		return nil, ErrNotElevated
	}

	names := ruleNames(spec.Applications)
	// Written before the first rule exists. A crash in between leaves the file
	// naming rules that were never created, and removing a rule that is not
	// there is a no-op — the opposite order would leave real rules with nothing
	// recording them.
	if err := writeState(enforcementState{
		PID: os.Getpid(), Listen: spec.ProxyAddr, Group: ruleGroup, RuleNames: names,
	}); err != nil {
		return nil, err
	}

	err := contain.WithCOMThread(func() error {
		rules, release, err := openRules()
		if err != nil {
			return err
		}
		defer release()

		// Clear our own names first: Add would otherwise stack a second rule
		// with the same name from a session that did not shut down cleanly.
		for _, name := range names {
			removeRule(rules, name)
		}
		for i, app := range spec.Applications {
			if err := addBlockRule(rules, names[i], app, spec.ProxyAddr); err != nil {
				// Roll back what this call created, so a failure leaves the
				// machine as it was found rather than half-enforced.
				for _, name := range names[:i] {
					removeRule(rules, name)
				}
				return err
			}
		}
		return nil
	})
	if err != nil {
		_ = clearState() // nothing was installed; do not leave a file claiming otherwise
		return nil, fmt.Errorf("install egress firewall rules: %w", err)
	}
	logger.Info("egress enforcement applied", "rules", len(names), "group", ruleGroup)

	var undone bool
	restore := func() error {
		if undone {
			return nil
		}
		undone = true
		err := contain.WithCOMThread(func() error {
			rules, release, err := openRules()
			if err != nil {
				return err
			}
			defer release()
			for _, name := range names {
				removeRule(rules, name)
			}
			logger.Info("egress enforcement removed", "rules", len(names))
			return nil
		})
		// Clear the state only once the rules are actually gone, so a failed
		// removal is still recoverable by the next start.
		if err != nil {
			return fmt.Errorf("remove egress firewall rules: %w", err)
		}
		return clearState()
	}
	return restore, nil
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

	var removed int
	if err := contain.WithCOMThread(func() error {
		rules, release, err := openRules()
		if err != nil {
			return err
		}
		defer release()
		for _, name := range state.RuleNames {
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
	var unk *win32.IUnknown
	if err := com.CoCreateInstance(
		&clsidNetFwRule,
		nil,
		com.CLSCTX_INPROC_SERVER,
		&windowsfirewall.IID_INetFwRule,
		&unk,
	); err != nil {
		return fmt.Errorf("CoCreateInstance(NetFwRule): %w", err)
	}
	if unk == nil {
		return fmt.Errorf("CoCreateInstance(NetFwRule): nil interface") //nolint:err113 // one-off guard
	}
	rule := (*windowsfirewall.INetFwRule)(unsafe.Pointer(unk))
	defer rule.Release()

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
