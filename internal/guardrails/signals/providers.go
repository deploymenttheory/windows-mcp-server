package signals

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// RegisterBuiltins wires the built-in tier-1 (local) guardrail providers into a
// registry. These are fast, offline, and auditable — but a local admin can spoof
// their inputs (dsregcmd/registry/enrollment), so they are defense-in-depth, not
// a hard boundary. The authoritative tier-2 checks are wired separately:
// RegisterGraph (Entra + Intune compliance) and RegisterRemotePolicy (may-run).
func RegisterBuiltins(reg *Registry) {
	reg.Register(Guardrail{
		ID:          "run-context",
		Description: "Process runs as an interactive user (not SYSTEM, not Session 0)",
		Check:       checkRunContext,
	})
	reg.Register(Guardrail{
		ID:          "mdm-enrolled",
		Description: "Device is MDM-enrolled",
		Check:       checkMDMEnrolled,
	})
	reg.Register(Guardrail{
		ID:          "entra-joined",
		Description: "Device is Entra/Azure-AD joined",
		Check:       checkEntraJoined,
	})
	reg.Register(Guardrail{
		ID:          "domain-joined",
		Description: "Device is joined to an AD domain",
		Check:       checkDomainJoined,
	})
	reg.Register(Guardrail{
		ID:          "os-enterprise-sku",
		Description: "OS is an Enterprise edition",
		Check:       checkEnterpriseSKU,
	})
	reg.Register(Guardrail{
		ID:          "device-allowlist",
		Description: "Device serial/hostname/Entra-id is on the allowlist (arg=path)",
		Check:       checkAllowlist,
	})
	reg.Register(Guardrail{
		ID:          "not-admin",
		Description: "Interactive user is NOT a local administrator",
		Check:       checkNotAdmin,
	})
	reg.Register(Guardrail{
		ID:          "logged-on-account",
		Description: "Logged-on user matches a regex (arg=regex)",
		Check:       checkLoggedOnAccount,
	})
	// remote-policy is live but token-less by default; RegisterRemotePolicy
	// overrides it with a bearer token when one is configured.
	reg.Register(Guardrail{
		ID:          "remote-policy",
		Description: "External may-run policy authorizes this device (arg=url)",
		Check:       remotePolicyCheck(""),
	})
}

func checkRunContext(_ context.Context, env *Env) Result {
	rc := env.Sys.RunContext()
	switch {
	case rc.TokenUnread:
		// Error, not fail: the device may well be fine, but this check could not
		// establish it. The engine scores an errored signal at the rule's severity,
		// so a policy that says deny still denies -- which is the point. Reporting
		// pass here, as a zero-valued RunContext used to, admitted the session on
		// the strength of a read that did not happen.
		return errf("run-context", "could not read the process token, so the run context is unknown")
	case rc.IsInteractiveUser():
		return pass("run-context", fmt.Sprintf("interactive user %q, session %d", rc.User, rc.SessionID))
	case rc.IsSystem:
		return fail("run-context", "process is running as SYSTEM; desktop automation requires an interactive user")
	default:
		return fail("run-context", fmt.Sprintf("non-interactive session %d", rc.SessionID))
	}
}

// ParseDsreg turns `dsregcmd /status` output into a key→value map. It is exported
// so the OS adapter can extract device identity (DeviceId, TenantId) once.
func ParseDsreg(output string) map[string]string { return dsregParse(output) }

// dsregParse turns `dsregcmd /status` output into a key→value map.
func dsregParse(output string) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(output))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, ":"); i > 0 {
			k := strings.TrimSpace(line[:i])
			v := strings.TrimSpace(line[i+1:])
			if k != "" {
				m[k] = v
			}
		}
	}
	return m
}

func isNull(s string) bool {
	s = strings.TrimSpace(s)
	return s == "" || strings.EqualFold(s, "NULL") || strings.EqualFold(s, "(null)")
}

func checkMDMEnrolled(ctx context.Context, env *Env) Result {
	out, err := env.Sys.RunShell(ctx, "dsregcmd /status")
	if err != nil {
		return errf("mdm-enrolled", "dsregcmd failed: "+err.Error())
	}
	m := dsregParse(out)
	if url := m["MdmUrl"]; !isNull(url) {
		return Result{ID: "mdm-enrolled", Status: Pass, Detail: "MDM: " + url, Data: map[string]any{"mdm_url": url}}
	}
	return fail("mdm-enrolled", "device is not MDM-enrolled (no MdmUrl)")
}

func checkEntraJoined(ctx context.Context, env *Env) Result {
	out, err := env.Sys.RunShell(ctx, "dsregcmd /status")
	if err != nil {
		return errf("entra-joined", "dsregcmd failed: "+err.Error())
	}
	m := dsregParse(out)
	if strings.EqualFold(m["AzureAdJoined"], "YES") {
		return pass("entra-joined", "Entra/Azure-AD joined (tenant "+m["TenantName"]+")")
	}
	return fail("entra-joined", "device is not Entra/Azure-AD joined")
}

func checkNotAdmin(_ context.Context, env *Env) Result {
	if env.Sys.IsAdmin() {
		return fail("not-admin", "interactive user is a member of the local Administrators group")
	}
	return pass("not-admin", "interactive user is not a local administrator")
}

func checkLoggedOnAccount(_ context.Context, env *Env) Result {
	pattern := env.Arg
	if pattern == "" {
		return errf("logged-on-account", "no pattern (use logged-on-account=<regex>)")
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return errf("logged-on-account", "invalid regex "+strconv.Quote(pattern)+": "+err.Error())
	}
	user := env.Sys.RunContext().User
	if re.MatchString(user) {
		return pass("logged-on-account", "logged-on user "+strconv.Quote(user)+" matches "+strconv.Quote(pattern))
	}
	return fail("logged-on-account", "logged-on user "+strconv.Quote(user)+" does not match "+strconv.Quote(pattern))
}

func checkDomainJoined(_ context.Context, env *Env) Result {
	d, err := env.Sys.DomainSKU()
	if err != nil {
		return errf("domain-joined", "WMI query failed: "+err.Error())
	}
	if d.PartOfDomain {
		return pass("domain-joined", "domain: "+d.Domain)
	}
	return fail("domain-joined", "device is not joined to an AD domain")
}

// enterpriseSKUs are OperatingSystemSKU values for Enterprise editions:
// Enterprise, EnterpriseN, EnterpriseE, EnterpriseEval, EnterpriseNEval, EnterpriseS.
var enterpriseSKUs = map[uint32]bool{
	4: true, 27: true, 70: true, 72: true, 84: true, 125: true,
}

func checkEnterpriseSKU(_ context.Context, env *Env) Result {
	d, err := env.Sys.DomainSKU()
	if err != nil {
		return errf("os-enterprise-sku", "WMI query failed: "+err.Error())
	}
	if enterpriseSKUs[d.OSSKU] || strings.Contains(strings.ToLower(d.OSCaption), "enterprise") {
		return pass("os-enterprise-sku", d.OSCaption)
	}
	return fail("os-enterprise-sku", "OS is not an Enterprise edition: "+d.OSCaption)
}

func checkAllowlist(_ context.Context, env *Env) Result {
	path := env.Arg
	if path == "" {
		return errf("device-allowlist", "no allowlist path (use device-allowlist=<path>)")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return errf("device-allowlist", "cannot read allowlist: "+err.Error())
	}
	allow := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		allow[strings.ToLower(line)] = true
	}
	id := env.Sys.DeviceIdentity()
	for _, cand := range []string{id.Serial, id.Hostname, id.EntraDeviceID} {
		if cand != "" && allow[strings.ToLower(cand)] {
			return pass("device-allowlist", "matched "+cand)
		}
	}
	return fail("device-allowlist", fmt.Sprintf("device not on allowlist (host=%q serial=%q)", id.Hostname, id.Serial))
}
