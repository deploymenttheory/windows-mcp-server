# Device policy configuration

The policy engine sits between the MCP caller and the tools. Before a tool runs, a
resource is read or a prompt is fetched, it evaluates device signals against the
rules in a policy document and decides what happens.

```
MCP client ──▶ audit ──▶ rug-pull ──▶ policy engine ──▶ tool handler
                                            │
                                      device signals
                          (MDM, Entra, Secure Boot, BitLocker, VBS, TPM, …)
```

```sh
windows-mcp-server stdio --policy-config C:\ProgramData\windows-mcp\policy.json
```

With no `--policy-config` the built-in default applies: the engine is present,
every declared signal is evaluated and every verdict recorded, and nothing is
refused.

## Verdicts

A rule states what happens when a signal it requires fails. The verdict for a
request is the **highest** severity among its failures.

| `on_fail` | | Effect |
|---|---|---|
| `allow` | green | The call proceeds. The failure is still recorded. |
| `warn` | amber | The call proceeds and the warning is attached to the result, so the model sees it and not only the operator. |
| `hold` | held | The call is suspended on an out-of-band human decision (see [Dual control](#dual-control-on_fail-hold)). It proceeds only if an approver says yes; a timeout denies. Stronger than a warning the model can ignore, weaker than an outright refusal, because a person can still let it through. |
| `deny` | red | The call is refused. Nothing latches: the next call is evaluated afresh, so a signal that recovers restores service without a restart. |
| `kill` | out of bounds | The kill switch trips and the containment ladder runs. |

Ordered `allow < warn < hold < deny < kill`; the verdict for a request is the
highest severity among its failures.

`"mode": "audit"` caps severity at `warn`. Signals are still read and every
verdict is still recorded, including what enforcing *would* have done — that is
the point of audit mode, and why it does not simply skip evaluation. Note this
caps `hold` too: an audit-mode device never suspends a call for approval, which
is what keeps audit mode observe-only.

## Argument constraints

A rule may also bound the arguments of the calls it matches; a violated bound
fails the rule at its `on_fail`, exactly like a failing required signal, and a
rule may carry constraints with an empty `require`:

```jsonc
{ "name": "bounded-typing",
  "match": {"tool": "Type"},
  "require": [],
  "constraints": {"text": {"max_length": 4096, "pattern": "^[\\x20-\\x7e]+$"}},
  "on_fail": "deny" }
```

Per argument: `min` / `max` (numbers, inclusive), `max_length` (strings, in
bytes), `pattern` (a regular expression, standard unanchored matching — write
`^…$` to anchor). Patterns are **RE2** (Go's `regexp`): no backtracking, so
evaluation is linear in the input and a policy author cannot write a pattern
that stalls the request path — a backreference does not compile and validation
refuses it. An absent argument fails, a wrong-typed argument fails, and an
omitted `arguments` object is an empty set in which every constrained argument
is absent — a caller cannot dodge a constraint by leaving things out. Failure
details name the argument and the bound, never the value: argument values stay
out of the audit chain for the same reason tool arguments are digested, not
recorded. Constraints on a `startup`-scope rule are refused at load (startup
subjects carry no arguments), and plan-time evaluation skips them — they are
spent where the arguments actually are, at call time.

## Document reference

```jsonc
{
  "version": 1,                    // required; a document this build cannot parse is refused
  "mode": "audit",                 // "audit" | "enforce"

  "signals": {                     // which signals this policy reads, and how fresh
    "run-context": { "ttl": "0s" },              // 0 = evaluate live on every request
    "bitlocker":   { "ttl": "60s" },
    "device-allowlist": { "ttl": "5m", "arg": "C:\\allow.txt" }
  },

  "rules": [
    { "name": "baseline",
      "match": { "toolset": "*" },              // "*" means every tool
      "require": ["run-context"],
      "on_fail": "deny" },

    { "name": "destructive",
      "match": { "annotation": "destructive" }, // read-only | destructive | open-world
      "require": ["bitlocker"],
      "on_fail": "deny" },

    { "name": "shell",
      "match": { "tool": ["PowerShell", "Registry"] },
      "require": ["mdm-enrolled"],
      "on_fail": "kill" },

    { "name": "admission",
      "match": { "scope": "startup" },          // evaluated once, before serving
      "require": ["run-context"],
      "on_fail": "deny" }
  ],

  "rate_limits": [
    { "name": "destructive-burst",
      "match": { "annotation": "destructive" },
      "window": "10s", "max": 3, "on_exceed": "deny" }
  ],

  "kill": {
    "triggers": {                  // sources with no severity of their own
      "posture_drift": true,       // a background re-evaluation stops admitting
                                   //   (needs a scope:"startup" rule -- see below)
      "rugpull": true,             // the served manifest changed after startup
      "heartbeat_gap": true,
      "sentinel": true             // a "kill" file appears in inflight.control_dir
    },
    "actions": {                   // applied in a fixed order; see killaction.go
      "isolate": true,             // firewall block-all (requires elevation)
      "lock": false,
      "shutdown": false,
      "shutdown_delay": "0s",
      "kill_procs": []
    }
  },

  "transparency": {
    "audit_destination": "stderr",        // "stderr", a file path, or a directory for one file per session
    "heartbeat": "30s",
    "recording_dir": "",           // non-empty records the session to video
    "evidence_dir": "",            // non-empty auto-seals a signed evidence bundle per session (needs a directory audit_destination)
    "banner": true,                // on-screen banner on a kill
    "status_addr": "",             // loopback status endpoint, e.g. 127.0.0.1:8177
    "status_token_env": "",        // env var NAME holding its bearer credential (preferred)
    "status_token": "",            // the credential inline (deprecated -- see below)
    "anchor": {                    // off-box publication of the audit chain head (default: off)
      "destination": "",           // "eventlog" writes the head to the Windows Application log
      "cadence": ""                // required when destination is set, e.g. "5m"
    },
    "export": {                    // ship the sealed evidence bundle off the device (default: off)
      "provider": "",              // "signed_url"; needs evidence_dir. Credentials come from
                                   // WINDOWS_MCP_EXPORT_* env vars, never from this document
      "timeout": ""                // upload budget, default "2m" -- it runs during shutdown
    }
  },

  "inflight": {
    "interval": "60s",             // background signal refresh + posture re-evaluation
    "control_dir": ""
  },

  "enforce_https": true,           // refuse plaintext http:// targets

  "credentials": {                 // governs how --credentials-file composes with the tool surface
    "acknowledge_toolset_exposure": []  // accept serving credentials next to "shell"/"filesystem"
  },

  "require_plan": [                // tools that may only run inside an approved plan (via Apply)
    { "annotation": "destructive" }   // a direct call to a matching tool is refused; same match syntax as a rule
  ],

  "telemetry": {                   // OTLP export; empty endpoint (the default) disables it
    "endpoint": "",                // "host:4318" or "https://collector:4318"
    "protocol": "http",            // only http is implemented
    "sample_ratio": 1.0            // trace sampling in [0,1]
  },

  "approvals": {                   // out-of-band authoriser for on_fail: hold rules; required if any rule uses it
    "webhook_url": "https://approvals.example/decide",  // http/https; POSTed each pending call, signed with WINDOWS_MCP_APPROVAL_KEY
    "timeout": "2m",               // a call still undecided at the deadline is denied (fails closed)
    "poll_interval": "5s"          // how often to re-poll while a decision is pending
  },

  "egress": {                      // device egress proxy; omit or disable to leave networking untouched
    "enabled": true,
    "allow": ["*.contoso.com", "login.microsoftonline.com"],
    "listen": "127.0.0.1:8181",    // loopback only
    "allow_ports": [443, 80],
    "applications": [],            // full .exe paths blocked from bypassing the proxy (needs elevation)
    "block_all_outbound": false,   // machine-wide default-deny (needs elevation)
    "set_system_proxy": false,     // point this user's WinINET settings at the proxy
    "allow_private_networks": false,
    "auth_token_env": ""           // env var NAME holding a Proxy-Authorization secret
  }
}
```

Unknown keys are rejected. A misspelled key would otherwise be dropped silently,
leaving you believing a control is in force when it is not.

### Matching

A rule's `match` selects the requests it covers.

- `tool` — by tool name.
- `toolset` — by toolset id; `"*"` matches every tool.
- `annotation` — `read-only`, `destructive`, `open-world`, taken from the tool's
  MCP annotations.
- `scope` — `call` (default) or `startup`.

Selectors within one `match` are **ANDed**; values within one selector are ORed.
So `{"toolset": "shell", "annotation": "destructive"}` covers only tools that are
both. Any field accepts a single string or an array.

`resources/read` and `prompts/get` are decided too. They are treated as read-only
subjects with no toolset, so `toolset: "*"` and `annotation: read-only` rules
cover them — a resource exposing the same desktop state as a tool must not be a
way around the rule covering that tool.

### Precedence

Requirements are the **union** across every matching rule, so adding a rule can
never drop a requirement another imposed.

Severity is attributed **per signal**: each required signal takes the `on_fail`
of the most specific rule that requires it.

```
tool  >  annotation  >  named toolset  >  toolset "*"
```

Ties break by document order, last wins, so a later rule can override an earlier
one at the same specificity.

`policy explain` prints exactly this for a given tool:

```sh
windows-mcp-server policy explain --policy-config policy.json --tool PowerShell
```

```
tool: PowerShell
  toolset=shell read-only=false destructive=true open-world=true

covered by 2 rule(s):
  baseline      requires [run-context]  on failure: deny
  destructive   requires [bitlocker]    on failure: deny

signals that must pass: [bitlocker run-context]
```

### What the policy does not cover

Two tools are served under every persona and belong to no toolset:
**`GuardrailStatus`** (read-only posture) and **`Kill`** (stop the session). They
are registered outside the tool inventory, so the policy tool index does not
contain them, and a rule matching `annotation: destructive` therefore does **not**
cover `Kill` — even though it is annotated destructive. This is deliberate:
denying the agent its own stop lever under bad posture would suppress a safety
action, and `Kill` routes to a graceful stop unless the policy has separately
armed containment. They are also outside the reach of `--exclude-tools` and
`--read-only`, so "always served" means always served.

The `FileSystem` tool is covered by policy like any other, but it additionally
refuses — regardless of policy — to read the credentials file or to write over the
audit log or the policy document. Those are guardrail paths; letting the agent
read a secret back or edit its own audit trail through a general file tool would
undo the controls around them.

### Rules that name a tool do not reach the other methods

`resources/read`, `prompts/get`, `completion/complete` and `subscriptions/listen`
are decided as read-only subjects that carry **no toolset and no tool name**. Only
`{"toolset": "*"}` or `{"annotation": "read-only"}` selects them.

This bites in a specific way worth knowing. A policy that gates credentials with
`{"tool": "Credentials"}`, or with `{"annotation": "destructive"}`, refuses every
mode of the tool — and still lets `completion/complete` return the *names* of the
installed credentials, because that request is a different method and matches
neither selector. Names are identifiers rather than secrets (the audit chain
records them, and `list` returns them), so this is an asymmetry rather than a
disclosure, and it is audited as `completion.complete` either way. But if you
intend "the agent may not enumerate credentials", a tool-name rule does not say
it.

Every policy in `policy/examples/` carries a `{"toolset": "*"}` rule, so none of
them has this gap. Add one to any policy you write:

```jsonc
{ "name": "baseline", "match": { "toolset": "*" }, "require": ["run-context"], "on_fail": "deny" }
```

Expressing "this resource specifically" is not something the schema supports yet;
see roadmap S14.

Note what the protected-path list does *not* include: the policy document is
protected against being **written**, not against being **read**, because a policy
is meant to be reviewable. Keep secrets out of it — use `status_token_env` rather than
`status_token`, and `egress.auth_token_env` rather than any inline value. The
`shell` toolset reaches every one of these paths with no protected-path check at
all, which is why serving it alongside `--credentials-file` requires an explicit
acknowledgement.

### Arming a trigger that has nothing to watch

`kill.triggers.posture_drift` re-evaluates the **startup rules** on each
`inflight.interval`. A policy that arms it without a `scope: "startup"` rule is
refused at load: with no startup rule there is nothing to re-evaluate, so the
monitor would run, log, and never trip — drift detection replaced by a timer. If
you want drift watched, write the admission rule you want re-checked:

```jsonc
{ "name": "admission", "match": { "scope": "startup" },
  "require": ["secure-boot", "bitlocker", "mdm-enrolled"], "on_fail": "deny" }
```

### Freshness

`ttl` is how long a reading stays usable. `dsregcmd`, WMI and `tpmtool` each cost
hundreds of milliseconds, and a desktop-automation session makes many small tool
calls, so evaluating every signal per request would dominate the session.

- `"ttl": "0s"` — read live on every request. Correct for cheap in-process
  signals such as `run-context`; expensive on anything backed by a shell or WMI.
- `"ttl": "60s"` — cached, refreshed in the background by the in-flight monitor.
  A reading can be up to its TTL out of date, bounded further by
  `inflight.interval`.

The cache starts **unread**, not passing, so the first calls of a session are
never admitted without having looked at the device.

## Signals

| id | What it checks | Cost |
|---|---|---|
| `run-context` | Interactive user, not SYSTEM or Session 0 | cheap |
| `not-admin` | Interactive user is not a local administrator | cheap |
| `device-allowlist` | Serial / hostname / Entra id on a list (`arg` = path) | cheap |
| `logged-on-account` | Logged-on user matches a regex (`arg` = regex) | cheap |
| `domain-joined` | Joined to an AD domain | WMI |
| `os-enterprise-sku` | OS is an Enterprise edition | WMI |
| `mdm-enrolled` | MDM-enrolled (`dsregcmd` MdmUrl) | shell |
| `entra-joined` | Entra / Azure-AD joined | shell |
| `secure-boot` | UEFI Secure Boot enabled | registry |
| `bitlocker` | Volumes are BitLocker-protected | WMI |
| `vbs` / `hvci` / `credential-guard` | Virtualization-based security running | WMI |
| `tpm-present` / `tpm-attestation-capable` | TPM state | `tpmtool` |
| `tpm-attested` | Nonce-fresh TPM platform attestation | `tpmtool`, elevated |
| `remote-policy` | External may-run endpoint authorizes (`arg` = URL) | network |
| `graph-entra-registered` | The device exists in Entra ID | network |
| `graph-entra-compliant` | Entra reports the device compliant | network |
| `graph-intune-enrolled` | The device is enrolled in Intune | network |
| `graph-intune-compliant` | Intune reports the device compliant | network |
| `graph-attested` | Intune holds a health-attestation record | network |

Write the id you want; there is no `graph-*` wildcard, and a signal name the
build does not know is refused at load. See [Remote signals](remote-signals.md)
for the app registration and permissions these need.

The Graph and `remote-policy` credentials come from the environment, never from
flags or this document — argv is world-readable and a policy is meant to be
checked in:

```
WINDOWS_MCP_GRAPH_TENANT, WINDOWS_MCP_GRAPH_CLIENT_ID,
WINDOWS_MCP_GRAPH_CLIENT_SECRET, WINDOWS_MCP_REMOTE_POLICY_TOKEN
```

## Working with a policy

```sh
windows-mcp-server policy validate --policy-config policy.json   # document + signal ids
windows-mcp-server policy check    --policy-config policy.json   # this device, right now
windows-mcp-server policy explain  --policy-config policy.json --tool PowerShell
windows-mcp-server policy test     fixtures/*.json               # asserted verdicts, no device
```

`validate` reads no device state, so it runs in CI on a machine with no TPM and
no domain. It reports every problem at once and exits 1:

```
error: policy policy.json: invalid policy:
  - unknown policy mode: "paranoid" (want "audit" or "enforce")
  - unknown signal: signals.nope is not a signal this build can evaluate
  - rule requires a signal that is not declared: rule "x" requires "bitlocker", which is not declared in signals
```

`check` reads every declared signal live, cache bypassed, and exits 2 when the
device is not admitted — so CI and health probes can gate on posture. It is
deliberately slow; that is what a diagnostic is for.

### Testing a policy

`policy test` turns a policy into something CI can exercise. A fixture is a
policy, a made-up device state, and a list of tool calls with the verdict each
should get:

```jsonc
{
  "policy": "../enterprise.json",          // relative to this fixture file; omit for the built-in default
  "device": { "mdm-enrolled": "fail" },    // signal -> pass | fail | error; unlisted signals default to pass
  "cases": [
    {
      "name": "an unmanaged device is denied PowerShell",
      "call": { "tool": "PowerShell", "toolset": "shell", "annotations": { "destructive": true } },
      "expect": {
        "severity": "deny",                // required: the verdict after the policy's mode is applied
        "failed_signals": ["mdm-enrolled"], // optional: the exact set that failed
        "rules": ["managed-device"]         // optional: rules that must have matched
      }
    }
  ]
}
```

It reads no live device state, so it runs anywhere and exits 1 on any mismatch —
a rule change that drops a requirement fails a test here rather than a call in the
field. Because `severity` is the verdict *after* the mode is applied, a fixture
against an `audit`-mode policy asserts the capped verdict (never above `warn`),
which is the truth of what that policy does; assert `deny`/`kill` against an
`enforce`-mode policy. See `policy/examples/tests/` for worked fixtures.

## Requiring a plan

`require_plan` is a list of selectors — same `tool` / `toolset` / `annotation`
syntax as a rule's `match` — naming tools that may only run inside an approved
plan. A **direct** call to a matching tool is refused (audited `plan.required`);
the same tool runs normally as a *step* of a plan submitted through the `Plan`
tool and executed by `Apply`. This is the preventive tier of plan-and-apply; see
[Plan and apply](plan-and-apply.md) for the whole model. The planning tools are
always exempt, so a `{ "toolset": "*" }` selector cannot deadlock the ability to
plan.

## Dual control (`on_fail: hold`)

A rule can dispose to `hold` instead of `deny` — when a required signal fails,
the call is **held** on a human decision rather than refused outright. This is
dual control: the model proposes, a person disposes. (The verdict word is `hold`;
the webhook that resolves it is still an *approval* — a person approves or denies
the held call.)

```json
"rules": [
  { "name": "human-in-the-loop-for-destructive-tools",
    "match":   { "annotation": "destructive" },
    "require": ["bitlocker"],
    "on_fail": "hold" }
],
"approvals": {
  "webhook_url": "https://approvals.corp.example/decide",
  "timeout": "2m",
  "poll_interval": "5s"
}
```

**How the decision is solicited.** This server holds no inbound listener — the
stdio-only posture is inviolable — so authorisation is asked *outbound*. When a
`hold` verdict fires, the enforcement point `POST`s a small JSON description of
the pending call to `approvals.webhook_url` and blocks that one request until the
answer comes back. The body carries identifiers and a **digest** of the arguments,
never the raw arguments — the authoriser decides on the call's identity, the same
discipline the audit chain follows:

```json
{ "request_id": "...", "session_id": "...", "method": "tools/call",
  "tool": "PowerShell", "args_sha256": "...", "rules": ["rule \"...\""],
  "failed_signals": ["bitlocker"], "requested_at": "...", "expires_at": "..." }
```

The webhook replies `{ "decision": "approve" | "deny" | "pending", "approver": "...",
"poll_url": "..." }`. A `pending` reply is re-polled (the `poll_url` with a GET, or
the webhook again) every `poll_interval` until it resolves or the `timeout` passes.

**Signing.** Each request carries an `X-WindowsMCP-Signature` header: the
HMAC-SHA256 of the body under the key in the `WINDOWS_MCP_APPROVAL_KEY` environment
variable, so the webhook can authenticate that the request is really from this
server. The key is an environment secret, never the policy document or a flag —
argv and the policy are both reviewable. Without a key, requests are unsigned and
the server warns.

**Fails closed.** A timeout denies. So does an unreachable webhook or an
unintelligible reply — an approval channel that is down must not become an open
door. All four outcomes are audited: `approval.requested` before the POST, then
`approval.decided` (or `approval.timed_out`), arguments digested, never raw.

**Constraints.** `hold` is only valid on **call-scope** rules — a startup
admission is a one-shot go/no-go with no request to suspend, and a rate limit fires
on a stream rather than one call, so both reject it at load. A rule that uses
`hold` **without** an `approvals` webhook is refused at load: dual control that
cannot ask anyone is not dual control. And `audit` mode caps `hold` at `warn`,
so an observe-only device never suspends a call.

**Plans, too.** A plan *step* that hits a `hold` rule blocks on the same
authoriser at `Apply` time — apply is never a way around dual control. See
[Plan and apply](plan-and-apply.md).

## Credentials exposure

`--credentials-file` installs secrets into the calling user's Windows Credential
Manager for the agent to *use* — the `Credentials` tool injects them as keystrokes
and never reads them back. But a credential in the Credential Manager can be read
by anything running as that user, so two toolsets defeat the guarantee from the
side: `shell` (PowerShell can `CredRead`) and `filesystem` (a Credential Manager
backup is just a file).

So the server **refuses to start** when `--credentials-file` is combined with
either toolset — whether selected directly, via `--toolsets`, or by a persona
(`first-line-support` carries `shell`; `qa-test-engineer` carries `filesystem`).
This matches the firewall tiers' stance: refuse rather than serve a weaker posture
than the document describes. The refusal is a configuration error, printed and
audited (`credentials.exposure.denied`) before anything is installed.

To accept the exposure deliberately, acknowledge it in the policy:

```jsonc
"credentials": { "acknowledge_toolset_exposure": ["shell"] }
```

Startup then proceeds, logs a warning, and records
`credentials.exposure.acknowledged` — so the residual risk is a recorded choice
rather than a silent hole. Only `"shell"` and `"filesystem"` are accepted values.

## Egress: the domains the device may reach

`egress` declares the destinations this device is allowed to connect to. When it
is enabled the server runs a loopback forward proxy that admits only those
destinations and refuses everything else.

A pattern is an exact hostname, an IP literal, or a wildcard:

| Pattern | Matches | Does not match |
|---|---|---|
| `contoso.com` | that host exactly | `www.contoso.com` |
| `*.contoso.com` | `contoso.com`, `www.contoso.com`, `a.b.contoso.com` | `fakecontoso.com` |
| `203.0.113.7` | that address, written any equivalent way | any other address |

`*` on its own is refused: an allowlist that admits everything is a
misconfiguration, not a policy. So is a pattern carrying a scheme, port or path,
because the extra part would silently not mean what it says.

### Three tiers, and the difference matters

| `enforcement` | What it means |
|---|---|
| `proxy-only` | The allowlist binds whatever is configured to use the proxy. Nothing stops an application ignoring it. No elevation needed. |
| `scoped` | The applications named in `applications` are given outbound-block firewall rules, so they cannot reach anything except the proxy. Needs elevation. |
| `global` | The machine's default outbound action becomes block, with an exception set for DNS, DHCP, NCSI, time, update and certificate revocation. Needs elevation. |

The tier in force is reported by `GuardrailStatus` and the status endpoint at
`server.egress.enforcement`, and the server logs a warning at startup when it is
`proxy-only` — so a proxy nothing is forced through is never mistaken for
enforcement. See [Egress setup](egress.md) for the end-to-end procedure.

All three tiers are implemented. `global` is the disruptive one — read the
section below before enabling it.

### Scoped enforcement

Each entry in `applications` gets one outbound firewall rule:

- **Direction** out, **action** block, **protocol any** — any rather than TCP on
  purpose, because QUIC is UDP and a TCP-only rule would leave HTTP/3 as an open
  path straight past the proxy.
- **Grouping** `WindowsMCP-Egress` and a deterministic name
  (`WindowsMCP-Egress-Block-<image>-<n>`), so cleanup never depends on guessing.
- Applied to all profiles, and only after the proxy is listening — blocking a
  program before it has anywhere to go would read as a broken network.

The blocked program can still reach `127.0.0.1`, because Windows Firewall does
not filter loopback. That is the entire mechanism: everything else is dropped,
and the proxy is the one route out.

**Elevation is required, and its absence is fatal.** A policy naming
`applications` in a process that cannot install rules refuses to start, after
auditing `egress.enforce.failed`. This is deliberately stricter than the kill
ladder, which degrades and continues: containment that cannot act mid-incident
is still better than nothing, whereas an operator whose document says these
programs cannot bypass the proxy must never get a server where they silently
can.

### Global enforcement: `block_all_outbound`

This sets the machine's **default outbound action to block** on all three
firewall profiles. Nothing reaches the network unless a rule permits it. Try it
in a VM first.

Because a bare default-deny would leave the machine looking broken rather than
governed, the server installs an exception set first — allow rules scoped to the
specific Windows service that needs each one:

| Exception | Service | Why it cannot be dropped |
|---|---|---|
| DNS | `Dnscache` | UDP/TCP 53 plus 443 for DoH; without it nothing resolves |
| DHCP | `Dhcp` | Without it the machine loses its lease and has no network at all |
| NCSI | `NlaSvc` | The connectivity probe; without it Windows reports "no internet" and apps stop trying rather than failing cleanly |
| Time | `W32Time` | Clock drift breaks TLS and Kerberos |
| Update | `wuauserv`, `BITS`, `DoSvc` | Security updates |
| Revocation | `CryptSvc` | Blocking it makes signature checks hang for seconds rather than fail |
| The proxy | this server's binary | Its route out, bounded to `allow_ports` |

Two orderings are deliberate. **Allow rules go in before the default flips** —
in the other order there is a window with no DNS and no DHCP, and a lease lost
in that window does not come back when the rules arrive. **Restoring reverses
it**: the default action goes back first, so a process dying mid-teardown leaves
a usable machine with only stale rules, which the next start clears.

Explicit `Allow` beats the block *default*, which is also why global mode cannot
be built from one catch-all `Block` rule — that would beat the exceptions.

### If the server dies without cleaning up

State outlives the process, so the server records what it is about to change in
`%ProgramData%\WindowsMCP\egress-rules.json` **before changing anything** — the
rule names, the per-profile default action to put back, and the prior WinINET
settings. Every subsequent start, including one where egress is now disabled,
restores whatever that file describes and audits `egress.recovered`.

The default action is restored first and unconditionally. Stale rules are
untidiness; a machine left default-deny with nothing running to proxy it has no
working network, which a user experiences as the computer being broken.

An unelevated start that finds state it cannot undo says so on every start
rather than leaving you guessing.

To recover by hand:

```powershell
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
netsh advfirewall firewall delete rule group="WindowsMCP-Egress"
```

### Interaction with the kill switch

If containment trips while global mode is active, the kill ladder isolates the
network by flipping the same default actions to block — but the exception rules
beat that default, so this server and the exempted services would keep their
route out during an incident. The `Finalize` hook therefore **disables** the
allow rules without restoring anything: undoing state there would countermand
the containment just applied. Full teardown stays with the normal exit path, and
a machine that reboots still contained is the correct direction to fail.

### What the proxy does per request

The order is deliberate. The allowlist is checked **before the name is
resolved**, so a refused host produces no DNS query — otherwise the refusal
itself becomes an outbound signal. Only then is the name resolved, and every
answer is checked against loopback, RFC1918, link-local (which covers the
`169.254.169.254` metadata address), CGNAT and multicast before one is dialled.
The connection goes to that vetted address, never to the name, so an allowed
name whose answer changes between the check and the dial cannot redirect it.

Set `allow_private_networks` if the allowlist deliberately names intranet hosts.
Loopback, link-local and multicast stay refused regardless.

TLS is never intercepted. A `CONNECT` request carries its target in cleartext,
which is all the allowlist needs — there is no certificate authority and nothing
is decrypted. The corollary is that an allowed domain is an opaque bidirectional
channel: this is a policy control, not a data-exfiltration control.

### Limits worth knowing

- The proxy binds loopback only, for the same reason the transport is stdio-only.
  Any local process can use it unless you set `auth_token_env`.
- `set_system_proxy` writes this user's WinINET settings. Applications are free
  to ignore them; that is why the firewall tiers exist.
- Blocked applications can still resolve names — they just cannot connect. DNS
  remains an unmonitored channel.
- Windows Firewall rules do not cover WSL2 or Hyper-V guest traffic, and
  UWP/AppContainer applications cannot reach a loopback proxy without a
  `CheckNetIsolation LoopbackExempt` grant.
- Rules name image paths, so a copy-renamed binary escapes `scoped`. `global` is
  the strong posture.
- A local administrator can undo any of it. This is a guardrail, not a boundary.

## Examples

`policy/examples/` holds seven starting points, each validated by the test suite:

| File | For |
|---|---|
| `audit.json` | First adoption. Declares a realistic signal set, refuses nothing. |
| `secure.json` | A managed device: MDM plus hardware posture for destructive tools. |
| `enterprise.json` | Entra-joined Enterprise fleet with VBS/HVCI and Credential Guard. |
| `locked-down.json` | Allowlisted, attested devices; drifting out of bounds kills the session. |
| `dual-control.json` | The riskiest calls held for a human to approve or refuse. |
| `egress.json` | A domain allowlist: the device may reach only the named destinations. |
| `evidence-export.json` | Sealed evidence shipped off the device at session end. |

## Migrating from the flags

The security flags are gone. Each maps to a field:

| Removed flag | Now |
|---|---|
| `--security` | `"mode": "enforce"` plus the rules you want; see `secure.json` |
| `--guardrails <mode>` | `"mode"` |
| `--guardrail <id>[=arg]` | an entry in `"signals"` plus a rule that requires it |
| `--with-mdm` | `"signals": {"mdm-enrolled": …}` + a rule requiring it |
| `--with-user-context` | `run-context` signal + rule |
| `--is-not-admin` | `not-admin` signal + rule |
| `--with-logged-on-account <re>` | `"logged-on-account": {"arg": "<re>"}` + rule |
| `--run-context` | removed; SYSTEM is detected, not declared |
| `--enterprise-guardrails` | see `enterprise.json` |
| `--guardrails-bypass` | removed; point at an audit-mode policy instead |
| `--circuit-breaker`, `--circuit-window`, `--circuit-threshold` | a `rate_limits` entry |
| `--enforce-https` | `"enforce_https": true` |
| `--inflight-interval` | `"inflight": {"interval": …}` |
| `--inflight-control-dir` | `"inflight": {"control_dir": …}` |
| `--with-logging` | `"transparency": {"audit_destination": …}` |
| `--heartbeat-interval` | `"transparency": {"heartbeat": …}` |
| `--with-video-session-recording`, `--record-dir` | `"transparency": {"recording_dir": …}` |
| `--guardrails-status-addr`, `--guardrails-status-token` | `"transparency": {"status_addr", "status_token_env"}` |
| `--with-kill-switch` | removed; a rule's `on_fail: "kill"` and the `kill.triggers` block arm it |
| `--kill-on-*` | `"kill": {"triggers": …}` |
| `--kill-action-*` | `"kill": {"actions": …}` |
| `--enable-tier2`, `--graph-*`, `--remote-policy-token` | environment variables (above) |

`--with-kill-switch` has no equivalent because it no longer has a job. A rule
saying `on_fail: "kill"` is the operator arming containment, in the same
document; requiring a second switch elsewhere in the file would mean a policy
that reads as arming the kill switch quietly does not. The `kill.triggers` block
covers only the sources with no severity of their own.

Flags that remain are the ones that select the served manifest or the
presentation, not policy: `--persona`, `--toolsets`, `--tools`,
`--exclude-tools`, `--read-only`, `--log-file`, `--overlay`, `--record-fps`,
`--record-codec`, `--credentials-file`.
