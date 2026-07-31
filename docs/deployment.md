# Deployment

Putting this on a machine you care about: where things live, what they need to be
locked down, and what the security model assumes you have already done.

- [Layout](#layout)
- [Locking down the files](#locking-down-the-files)
- [Running at logon](#running-at-logon)
- [Pairing with OS controls](#pairing-with-os-controls)
- [Rollout order](#rollout-order)

---

## Layout

Nothing here is enforced by the server — it takes paths as configuration. But the
security model assumes the agent cannot rewrite its own policy, and that only
works if the files sit somewhere the automated user cannot modify.

```
C:\Program Files\windows-mcp\
    windows-mcp-server.exe          binary, admin-writable only

C:\ProgramData\windows-mcp\
    policy.json                     the device policy
    creds.json                      credentials (if used)
    audit.jsonl                     the audit chain
    recordings\                     session video

C:\ProgramData\WindowsMCP\
    egress-rules.json               written by the server; do not edit
```

The last one is not yours to place, and note the different directory — the egress
subsystem owns `%ProgramData%\WindowsMCP\` and uses it to recover firewall state
after a crash.

---

## Locking down the files

The important asymmetry: the **user the agent runs as** must be able to *read*
the policy and *not* be able to *write* it. Otherwise a compromised session can
rewrite the rules that govern it.

```powershell
$dir = "C:\ProgramData\windows-mcp"

icacls $dir /inheritance:r
icacls $dir /grant:r "BUILTIN\Administrators:(OI)(CI)F"
icacls $dir /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F"
icacls $dir /grant:r "BUILTIN\Users:(OI)(CI)RX"       # read-only for the agent's user
```

Then tighten the credentials file further — it must not be readable by the broad
groups at all, and the server refuses to start if it is:

```powershell
icacls "$dir\creds.json" /inheritance:r
icacls "$dir\creds.json" /grant:r "$($env:USERDOMAIN)\$($env:USERNAME):(R)"
icacls "$dir\creds.json" /grant:r "NT AUTHORITY\SYSTEM:(F)"
icacls "$dir\creds.json" /grant:r "BUILTIN\Administrators:(F)"
```

See [Credentials](credentials.md#securing-the-file) for exactly which principals
are refused and why a Unix permission check would prove nothing.

**The audit log needs append access for the agent's user** but should not be
freely rewritable. There is no way to express append-only cleanly in an ACL for a
file the process also opens for writing — if tamper-evidence matters more than
convenience, ship entries off the box (`audit_sink` to a file, collected by your
agent) and treat the local copy as a buffer. The hash chain is what detects
editing; the ACL only raises the cost.

---

## Running at logon

The server drives an interactive desktop, so it needs an interactive session. It
cannot usefully run as a service — under SYSTEM it detects Session 0 and drops
every desktop-automation toolset (see
[What SYSTEM changes](toolsets-and-personas.md#what-system-changes)).

For an unattended RPA machine, the usual arrangement is:

1. **Autologon** to a dedicated, low-privilege account.
2. **Keep the session unlocked** — a locked session is the secure desktop, which
   no user-session process can see or drive.
3. **A scheduled task at logon** running the server, so it is present before the
   journey starts.

```powershell
$action  = New-ScheduledTaskAction -Execute "C:\Program Files\windows-mcp\windows-mcp-server.exe" `
             -Argument "stdio --policy-config C:\ProgramData\windows-mcp\policy.json"
$trigger = New-ScheduledTaskTrigger -AtLogOn -User "CONTOSO\rpa-runner"
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName "windows-mcp-server" -Action $action -Trigger $trigger `
  -Settings $settings -RunLevel Limited -User "CONTOSO\rpa-runner"
```

`-RunLevel Limited` is deliberate — run non-elevated unless you need the
elevation-only features, and see the note below.

> An autologon password is stored in the registry (LSA secrets) and is readable
> by local administrators. Use a dedicated account with no rights beyond the
> machine, and treat the machine as disposable.

### When you do need elevation

Two features require it: egress `applications` / `block_all_outbound`, and TPM
attestation (`tpm-attested`). Everything else works unelevated, and the kill
ladder degrades honestly — elevation-only rungs are skipped and audited rather
than failing the trip.

Elevating the whole server widens what a compromised session can do. If you only
need the egress firewall tiers, that is the trade to weigh: enforcement that
cannot be bypassed, against a process with more privilege.

---

## Pairing with OS controls

The security architecture is explicit that the local device signals are
**auditable defense-in-depth, not a hard boundary** — a local administrator can
spoof them. It only adds up if you also have:

- **WDAC or AppLocker**, so the binary that runs is the binary you shipped, and
  the agent cannot execute arbitrary tooling. This is the control that matters
  most, because `PowerShell` and `App` can otherwise launch anything.
- **Code signing** on the binary, so WDAC has something durable to key on.
- **Conditional Access**, so a device that drops out of compliance loses access
  to the resources the agent would reach — enforcement that does not depend on
  this process behaving.
- **Disk encryption**, since the credentials file and recordings sit on disk.

Without these, the policy engine is a good audit trail and a real speed bump, but
a local admin can go around it.

---

## Rollout order

Each step is safe to sit on for a while.

1. **Audit mode, no enforcement.** Copy `policy/examples/audit.json`, point the
   server at it, and let it run. Every verdict is recorded with the severity
   enforcing *would* have applied.
2. **Read the audit log.** Look for `policy.decision` entries whose intended
   verdict is deny. Those are the calls that will break when you flip the mode.
3. **Switch to `"mode": "enforce"`** once that list is empty or understood.
4. **Arm the kill triggers** you want, one at a time. Watch for
   `killswitch.disarmed` — that is a trigger firing while its switch is off, and
   it tells you what would have happened.
5. **Add containment actions** last. `isolate` before `lock` before `shutdown`.
6. **Egress**, working up the tiers — proxy-only, then scoped, then global — with
   [its own verification at each step](egress.md).

At every stage, `policy validate` runs in CI and `policy check` gates a health
probe:

```powershell
.\windows-mcp-server.exe policy validate --policy-config policy.json   # exits 1 on a bad document
.\windows-mcp-server.exe policy check    --policy-config policy.json   # exits 2 if this device is not admitted
```

---

## Related

- [Getting started](getting-started.md) — build and first run
- [Policy configuration](policy-config.md) — the document schema
- [Monitoring](monitoring.md) — the status endpoint and audit log
- [VM isolation](vm-isolation.md) — for untrusted workloads
- [Security architecture](security-architecture.md) — the trust model in full
