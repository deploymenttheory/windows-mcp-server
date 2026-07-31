//go:build windows && (amd64 || arm64)

package egress

import (
	"fmt"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networkmanagement/windowsfirewall"
)

// svchost is where Windows' own network clients live. Scoping a rule to it
// without a service name would open every service inside it, which is why each
// exception below names one.
const svchost = `%SystemRoot%\System32\svchost.exe`

// exception is one allow rule that keeps a default-deny machine usable.
//
// The set exists because flipping DefaultOutboundAction to block stops far more
// than an operator intends. Without DNS the machine resolves nothing; without
// DHCP it loses its lease and has no network at all; without NCSI the tray
// reports "no internet" and applications short-circuit off that state rather
// than trying; without update, time and revocation the machine quietly rots.
//
// Explicit Allow beats the block *default*, which is also why global mode
// cannot be built from a catch-all Block rule — that would beat these.
type exception struct {
	name string
	// service is the svchost service name; empty means a plain application.
	service string
	app     string
	// protocol is a NET_FW_IP_PROTOCOL; ports are only legal on TCP and UDP.
	protocol windowsfirewall.NET_FW_IP_PROTOCOL
	ports    string
	why      string
}

// defaultExceptions is the machine-usability set applied with global block.
//
// It is deliberately narrow: every entry is a Windows component that the OS
// cannot function without, scoped to the service that needs it and the ports it
// needs. None of them is a route an agent can use — they are svchost services,
// not the workload.
func defaultExceptions() []exception {
	tcp := windowsfirewall.NET_FW_IP_PROTOCOL_TCP
	udp := windowsfirewall.NET_FW_IP_PROTOCOL_UDP
	return []exception{
		{
			name: "DNS-UDP", service: "Dnscache", app: svchost,
			protocol: udp, ports: "53",
			why: "name resolution; without it the machine resolves nothing",
		},
		{
			name: "DNS-TCP", service: "Dnscache", app: svchost,
			protocol: tcp, ports: "53,443",
			why: "DNS over TCP, and DoH on 443 which Windows 11 uses by default",
		},
		{
			name: "DHCP", service: "Dhcp", app: svchost,
			protocol: udp, ports: "67,68,546,547",
			why: "address lease; without it the machine loses its network entirely",
		},
		{
			name: "NTP", service: "W32Time", app: svchost,
			protocol: udp, ports: "123",
			why: "clock sync; drift breaks TLS and Kerberos",
		},
		{
			name: "NCSI", service: "NlaSvc", app: svchost,
			protocol: tcp, ports: "80,443",
			why: "connectivity probe; without it Windows reports no internet and apps stop trying",
		},
		{
			name: "WindowsUpdate", service: "wuauserv", app: svchost,
			protocol: tcp, ports: "80,443",
			why: "security updates",
		},
		{
			name: "BITS", service: "BITS", app: svchost,
			protocol: tcp, ports: "80,443",
			why: "background transfer used by update and telemetry-free servicing",
		},
		{
			name: "DeliveryOptimization", service: "DoSvc", app: svchost,
			protocol: tcp, ports: "80,443",
			why: "update delivery",
		},
		{
			name: "CryptSvc", service: "CryptSvc", app: svchost,
			protocol: tcp, ports: "80,443",
			why: "certificate revocation; blocking it makes signature checks hang rather than fail",
		},
	}
}

// exceptionRuleName is the deterministic name for an exception rule.
func exceptionRuleName(e exception) string {
	return fmt.Sprintf("%s-Allow-%s", ruleGroup, e.name)
}

// proxyAllowRuleName is the rule permitting the server's own binary out, which
// is what makes the proxy reachable once the default is block.
func proxyAllowRuleName() string { return ruleGroup + "-Allow-Proxy" }

// addExceptionRule creates one service-scoped allow rule.
func addExceptionRule(rules *windowsfirewall.INetFwRules, e exception) error {
	name := exceptionRuleName(e)
	rule, release, err := newRuleObject()
	if err != nil {
		return err
	}
	defer release()

	steps := []struct {
		what string
		err  error
	}{
		{"name", withBSTR(name, rule.Put_Name)},
		{"description", withBSTR("windows-mcp-server egress exception: "+e.why, rule.Put_Description)},
		{"application", withBSTR(e.app, rule.Put_ApplicationName)},
		{"grouping", withBSTR(ruleGroup, rule.Put_Grouping)},
		{"protocol", rule.Put_Protocol(int32(e.protocol))},
		{"ports", withBSTR(e.ports, rule.Put_RemotePorts)},
		{"direction", rule.Put_Direction(windowsfirewall.NET_FW_RULE_DIR_OUT)},
		{"action", rule.Put_Action(windowsfirewall.NET_FW_ACTION_ALLOW)},
		{"profiles", rule.Put_Profiles(int32(windowsfirewall.NET_FW_PROFILE2_ALL))},
		{"enabled", rule.Put_Enabled(foundation.VARIANT_TRUE)},
	}
	if e.service != "" {
		steps = append(steps, struct {
			what string
			err  error
		}{"service", withBSTR(e.service, rule.Put_ServiceName)})
	}
	for _, step := range steps {
		if step.err != nil {
			return fmt.Errorf("set exception %s %s: %w", name, step.what, step.err)
		}
	}
	if err := rules.Add(rule); err != nil {
		return fmt.Errorf("add exception rule %q: %w", name, err)
	}
	return nil
}

// addProxyAllowRule lets this server's own binary reach the internet, which is
// the whole point of the arrangement: everything else is blocked and the proxy
// is the one way out.
func addProxyAllowRule(rules *windowsfirewall.INetFwRules, exePath, ports string) error {
	name := proxyAllowRuleName()
	rule, release, err := newRuleObject()
	if err != nil {
		return err
	}
	defer release()

	for _, step := range []struct {
		what string
		err  error
	}{
		{"name", withBSTR(name, rule.Put_Name)},
		{"description", withBSTR(
			"windows-mcp-server egress proxy: the only permitted route to approved destinations",
			rule.Put_Description)},
		{"application", withBSTR(exePath, rule.Put_ApplicationName)},
		{"grouping", withBSTR(ruleGroup, rule.Put_Grouping)},
		{"protocol", rule.Put_Protocol(int32(windowsfirewall.NET_FW_IP_PROTOCOL_TCP))},
		{"ports", withBSTR(ports, rule.Put_RemotePorts)},
		{"direction", rule.Put_Direction(windowsfirewall.NET_FW_RULE_DIR_OUT)},
		{"action", rule.Put_Action(windowsfirewall.NET_FW_ACTION_ALLOW)},
		{"profiles", rule.Put_Profiles(int32(windowsfirewall.NET_FW_PROFILE2_ALL))},
		{"enabled", rule.Put_Enabled(foundation.VARIANT_TRUE)},
	} {
		if step.err != nil {
			return fmt.Errorf("set proxy allow rule %s: %w", step.what, step.err)
		}
	}
	if err := rules.Add(rule); err != nil {
		return fmt.Errorf("add proxy allow rule %q: %w", name, err)
	}
	return nil
}

// setRuleEnabled flips a rule on or off by name, for the kill-path suspend that
// must weaken egress without restoring the machine's default actions.
func setRuleEnabled(rules *windowsfirewall.INetFwRules, name string, enabled bool) error {
	b := foundation.SysAllocString(name)
	defer foundation.SysFreeString(b)
	rule, err := rules.Item(b)
	if err != nil || rule == nil {
		return nil // absent is not an error on a best-effort path
	}
	defer rule.Release()

	value := foundation.VARIANT_FALSE
	if enabled {
		value = foundation.VARIANT_TRUE
	}
	if err := rule.Put_Enabled(value); err != nil {
		return fmt.Errorf("set %q enabled=%v: %w", name, enabled, err)
	}
	return nil
}
