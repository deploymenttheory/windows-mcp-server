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
| `deny` | red | The call is refused. Nothing latches: the next call is evaluated afresh, so a signal that recovers restores service without a restart. |
| `kill` | out of bounds | The kill switch trips and the containment ladder runs. |

`"mode": "audit"` caps severity at `warn`. Signals are still read and every
verdict is still recorded, including what enforcing *would* have done — that is
the point of audit mode, and why it does not simply skip evaluation.

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
    "audit_sink": "stderr",        // "stderr" or a file path for append-only JSONL
    "heartbeat": "30s",
    "recording_dir": "",           // non-empty records the session to video
    "banner": true,                // on-screen banner on a kill
    "status_addr": "",             // loopback status endpoint, e.g. 127.0.0.1:8177
    "status_token": ""
  },

  "inflight": {
    "interval": "60s",             // background signal refresh + posture re-evaluation
    "control_dir": ""
  },

  "enforce_https": true            // refuse plaintext http:// targets
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
| `graph-*` | Entra + Intune compliance | network |

The `graph-*` and `remote-policy` credentials come from the environment, never
from flags or this document — argv is world-readable and a policy is meant to be
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

## Examples

`policy/examples/` holds four starting points, each validated by the test suite:

| File | For |
|---|---|
| `audit.json` | First adoption. Declares a realistic signal set, refuses nothing. |
| `secure.json` | A managed device: MDM plus hardware posture for destructive tools. |
| `enterprise.json` | Entra-joined Enterprise fleet with VBS/HVCI and Credential Guard. |
| `locked-down.json` | Allowlisted, attested devices; drifting out of bounds kills the session. |

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
| `--with-logging` | `"transparency": {"audit_sink": …}` |
| `--heartbeat-interval` | `"transparency": {"heartbeat": …}` |
| `--with-video-session-recording`, `--record-dir` | `"transparency": {"recording_dir": …}` |
| `--guardrails-status-addr`, `--guardrails-status-token` | `"transparency": {"status_addr", "status_token"}` |
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
