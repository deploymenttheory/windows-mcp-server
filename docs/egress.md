# Egress setup

How to stand up the device egress proxy, tier by tier, and verify each one
actually works. For the pattern syntax, the request-path guarantees and the full
field reference, see [Egress in the policy schema](policy-config.md#egress-the-domains-the-device-may-reach).

Work up the tiers in order. Each is useful on its own, and each is a prerequisite
for understanding the next.

| Tier | Elevation | Blast radius |
|---|---|---|
| [1. Proxy only](#tier-1-proxy-only) | No | Nothing outside the proxy |
| [2. Scoped](#tier-2-scoped-enforcement) | Yes | The named applications |
| [3. Global](#tier-3-global-default-deny) | Yes | The whole machine — **VM first** |

---

## Tier 1: proxy only

Start here. Nothing on the machine changes; you get a proxy that admits only your
allowlist, and anything configured to use it is constrained.

```jsonc
"egress": {
  "enabled": true,
  "allow": ["*.contoso.com", "login.microsoftonline.com"],
  "listen": "127.0.0.1:8181",
  "allow_ports": [443]
}
```

Start the server and confirm the proxy is listening — startup logs it, and warns
that this tier is advisory:

```
INFO  egress proxy listening addr=127.0.0.1:8181 patterns=2 enforcement=proxy-only
WARN  egress proxy is advisory: no applications are blocked from bypassing it
```

### Verify it

```powershell
# Allowed: tunnels, returns the page
curl.exe -x http://127.0.0.1:8181 https://www.contoso.com

# Denied: 403 with an actionable message, and no DNS query is made
curl.exe -x http://127.0.0.1:8181 https://tracker.example
```

The denial should be effectively instant. That speed is the evidence that the
allowlist was consulted *before* the name was resolved — a refused host never
generates a DNS query.

curl hides the refusal body on a failed `CONNECT`. To read it:

```powershell
$c = New-Object Net.Sockets.TcpClient('127.0.0.1',8181)
$w = New-Object IO.StreamWriter($c.GetStream())
$w.Write("CONNECT tracker.example:443 HTTP/1.1`r`nHost: tracker.example:443`r`n`r`n"); $w.Flush()
(New-Object IO.StreamReader($c.GetStream())).ReadToEnd()
$c.Close()
```

### Pointing clients at it

**Automatically, for this user.** `"set_system_proxy": true` writes the WinINET
settings (`ProxyEnable`, `ProxyServer`, `ProxyOverride=<local>`) and signals
running processes to re-read them. Chromium-based browsers, the Settings UI and
.NET Framework clients follow it. No elevation needed, and the prior values are
restored on exit.

**Per browser**, if you would rather not touch user settings:

```powershell
& "C:\Program Files\Google\Chrome\Application\chrome.exe" --proxy-server="http://127.0.0.1:8181"
msedge.exe --proxy-server="http://127.0.0.1:8181"
```

Firefox does not read WinINET by default — set it under Settings → Network
Settings, or `network.proxy.type=1` with `network.proxy.ssl`/`ssl_port`.

**Command-line tools** read the environment:

```powershell
$env:HTTPS_PROXY = "http://127.0.0.1:8181"
$env:HTTP_PROXY  = "http://127.0.0.1:8181"
```

### Requiring a credential

Any local process can use a loopback proxy. To restrict it, name an environment
variable holding a shared secret:

```jsonc
"egress": { "auth_token_env": "WINDOWS_MCP_EGRESS_TOKEN" }
```

The variable holds the value; the policy document only names the variable, since
the document is meant to be reviewable and checked in. Clients present it as
`Proxy-Authorization`:

```powershell
$env:WINDOWS_MCP_EGRESS_TOKEN = "a-long-random-string"
curl.exe -x http://127.0.0.1:8181 --proxy-header "Proxy-Authorization: Bearer a-long-random-string" https://www.contoso.com
```

Without it, requests get `407` and never reach the resolver.

---

## Tier 2: scoped enforcement

Now stop the named applications going around the proxy. Add their **full image
paths**:

```jsonc
"egress": {
  "enabled": true,
  "allow": ["*.contoso.com"],
  "allow_ports": [443],
  "set_system_proxy": true,
  "applications": [
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
  ]
}
```

Each entry gets one outbound-block firewall rule covering **all protocols** — TCP
and UDP, so QUIC/HTTP-3 cannot slip past on UDP/443. Windows Firewall does not
filter loopback, so the blocked application can still reach the proxy. That is
the whole mechanism.

**This requires elevation, and its absence is fatal.** An unelevated server with
`applications` set refuses to start rather than serving a weaker posture than the
document describes:

```
error: egress enforcement requires an elevated process: egress.applications and
egress.block_all_outbound install firewall rules, so the server must run elevated
```

### Finding the right paths

The rule matches the image path exactly, so get it from the running process:

```powershell
Get-Process chrome, msedge -ErrorAction SilentlyContinue |
  Select-Object -ExpandProperty Path -Unique
```

Note the honest limit: a copy of the binary under another path is not covered.
Scoped mode constrains named workloads, not a determined adversary — tier 3 is
the strong form.

### Verify it

```powershell
# The rules exist and are enabled
Get-NetFirewallRule -Group "WindowsMCP-Egress" |
  Format-Table DisplayName, Direction, Action, Enabled

# Direct connection from the blocked app fails; the proxied path works.
# (Test with a blocked binary, not with curl, unless curl is in the list.)
```

After a clean shutdown the group should be empty:

```powershell
Get-NetFirewallRule -Group "WindowsMCP-Egress"   # expect: nothing
```

---

## Tier 3: global default-deny

**Do this in a VM first.** This sets the machine's default outbound action to
block on all three profiles. Everything on the machine is dropped unless a rule
permits it.

```jsonc
"egress": {
  "enabled": true,
  "allow": ["*.contoso.com"],
  "allow_ports": [443],
  "block_all_outbound": true,
  "set_system_proxy": true
}
```

The server installs an exception set *before* flipping the default — allow rules
scoped to the specific Windows service that needs each one. Without them a
default-deny machine does not merely restrict the agent, it stops working:

| Exception | Service | What breaks without it |
|---|---|---|
| DNS (53, and 443 for DoH) | `Dnscache` | Nothing resolves, anywhere |
| DHCP | `Dhcp` | The lease is lost; no network at all |
| NCSI probe | `NlaSvc` | Windows reports "no internet"; apps stop trying rather than failing cleanly |
| NTP | `W32Time` | Clock drift breaks TLS and Kerberos |
| Update | `wuauserv`, `BITS`, `DoSvc` | No security updates |
| Revocation | `CryptSvc` | Signature checks hang for seconds instead of failing |
| The proxy | this binary | The one permitted route out, bounded to `allow_ports` |

### Pre-flight checklist

Before enabling this on any machine you care about:

- [ ] It is a VM, or you have console access that does not depend on the network
- [ ] You know the recovery commands below and can run them locally
- [ ] The machine is not domain-joined in a way that needs Kerberos/LDAP to log in
      (those are **not** in the exception set — add explicit allow rules first)
- [ ] You have checked whether anything else on the machine needs egress: backup
      agents, EDR, management agents, licence checks
- [ ] RDP or SSH access, if you rely on it, has an inbound path (inbound is
      unaffected) **and** does not need outbound to authenticate

### Verify it

```powershell
netsh advfirewall show allprofiles | Select-String "Firewall Policy"
# expect: BlockInbound,BlockOutbound

Resolve-DnsName www.contoso.com          # should work — DNS is exempted
w32tm /resync                            # should work — time is exempted
Test-NetConnection www.example.com -Port 443   # should FAIL — not the proxy
curl.exe -x http://127.0.0.1:8181 https://www.contoso.com   # should work
```

Then confirm the tier is what you think it is:

```powershell
curl.exe -H "Authorization: Bearer $token" http://127.0.0.1:8177/guardrails |
  ConvertFrom-Json | Select-Object -ExpandProperty server |
  Select-Object -ExpandProperty egress
# enforcement should read: global
```

---

## Recovery

State outlives the process. Before changing anything the server writes what it is
about to do to `%ProgramData%\WindowsMCP\egress-rules.json` — rule names, the
per-profile default action to restore, and the prior WinINET settings. **Every**
subsequent start, including one where egress is now disabled, undoes whatever
that file describes and audits `egress.recovered`.

The default action is restored first and unconditionally: stale rules are
untidiness, but a machine left default-deny with nothing proxying for it has no
working network.

If the server cannot recover — it is not elevated, or the state file is corrupt —
it says so on every start. To fix it by hand:

```powershell
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
netsh advfirewall firewall delete rule group="WindowsMCP-Egress"
```

If `set_system_proxy` was on and did not get restored:

```powershell
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" ProxyEnable 0
```

---

## Known limits

These are honest boundaries, not bugs:

- **UWP / Store apps cannot reach a loopback proxy** without an exemption:
  `CheckNetIsolation.exe LoopbackExempt -a -n=<PackageFamilyName>` (elevated).
  List families with `Get-AppxPackage | Select PackageFamilyName`.
- **WSL2 and Hyper-V guests are not covered.** Their traffic does not traverse
  host firewall rules; that needs the separate Hyper-V firewall.
- **DNS remains available to blocked apps.** They cannot connect, but they can
  still resolve — so DNS stays an unmonitored side channel.
- **Scoped rules match image paths.** A copy-renamed binary escapes them.
- **An allowed domain is an opaque bidirectional channel.** TLS is never
  intercepted — there is no CA and nothing is decrypted — so this is a policy
  control, not a data-exfiltration control.
- **A local administrator can undo all of it.** This is a guardrail, not a
  security boundary.

---

## Related

- [Policy configuration](policy-config.md#egress-the-domains-the-device-may-reach) — field reference and pattern syntax
- [Monitoring](monitoring.md) — reading `server.egress` counters
- [Security architecture](security-architecture.md) — where egress sits in the stack
- `policy/examples/egress.json` — a complete working document
