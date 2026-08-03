# Monitoring: status endpoint and audit log

Two surfaces let something outside the agent see what the server is doing: a
loopback HTTP endpoint for live posture, and an append-only hash-chained audit
log for the record. Neither is exposed as a tool, so the agent cannot switch
either off.

- [The status endpoint](#the-status-endpoint) — live posture for health probes
- [The audit log](#the-audit-log) — what is recorded, and how to verify it

---

## The status endpoint

Off by default. Enable it in the policy document:

```jsonc
"transparency": {
  "status_addr": "127.0.0.1:8177",
  "status_token": "a-long-random-string"
}
```

Both fields are validated at load. `status_addr` must be a loopback address —
this server does not expose listeners the network can reach — and setting it
without a `status_token` is refused, because any local process could otherwise
read the device posture and trip the kill switch.

### Routes

| Method | Path | Purpose |
|---|---|---|
| GET | `/guardrails` | Full posture document |
| GET | `/healthz` | Identical to `/guardrails` — same handler, for probes that expect that name |
| POST | `/revoke` | Trips the kill switch. Returns `202 Accepted` |

Authentication is a bearer token, compared in constant time:

```sh
curl -H "Authorization: Bearer a-long-random-string" http://127.0.0.1:8177/guardrails
```

A wrong or missing token returns `401`. `/revoke` refuses anything but POST with
`405`.

### The status code is part of the answer

**`/guardrails` returns `403` when the device is not admitted or the kill switch
has tripped**, and `200` otherwise. The body is the same document either way.

This trips up naive health probes: a monitor that only checks for `200` will
report the server as *down* when it is running perfectly and correctly refusing
to act on a non-compliant device. Decide which you are measuring:

```sh
# "is the process alive" — accept 403 as alive
curl -sf -o /dev/null -w '%{http_code}' ... | grep -qE '200|403'

# "is the device allowed to act" — 200 only
curl -sf -o /dev/null ...
```

### Response shape

The `Decision` fields are inlined at the top level, with the always-on server
snapshot under `server`:

```jsonc
{
  "device":      { "hostname": "…", "serial": "…" },
  "run_context": { "is_system": false, "session_id": 1, "elevated": false, "user": "…" },
  "mode":        "enforce",
  "results":     [ { "id": "bitlocker", "status": "pass" } ],
  "admit":       true,
  "reasons":     ["…"],          // present when admit is false
  "timestamp":   "2026-07-31T…",
  "session_id":  "…",

  "server": {
    "uptime_sec":         1234.5,
    "tool_manifest_hash": "…",   // rug-pull baseline
    "heartbeat_seq":      42,
    "heartbeat_age_sec":  3.1,
    "audit_seq":          1180,
    "audit_chain_head":   "…",   // hash of the newest entry
    "killed":             false,
    "egress": {                   // omitted entirely when egress is off
      "listen":         "127.0.0.1:8181",
      "enforcement":    "scoped",
      "allow_patterns": 3,
      "allowed":        118,
      "denied":         4,
      "denied_host":    3,
      "denied_address": 1
    }
  },
  "killed":      false,
  "kill_reason": "…"             // present when killed
}
```

`GuardrailStatus`, the agent-facing tool, returns this same document — so what
the model sees and what your monitoring sees cannot drift apart.

### What to alert on

| Signal | Meaning |
|---|---|
| `heartbeat_age_sec` exceeding a few multiples of `transparency.heartbeat` | The server has stalled or been killed; the in-process watchdog also fires |
| `killed: true` | Containment has run. `kill_reason` says why |
| `admit: false` | The device stopped meeting policy mid-session |
| `tool_manifest_hash` changing | Rug pull, or a legitimate restart with different toolsets |
| `audit_seq` not advancing while calls happen | The audit sink is failing |
| `server.egress.enforcement` unexpectedly `proxy-only` | Enforcement was requested but the tier in force is advisory |

---

## The audit log

Every decision, action and security event becomes an append-only entry that
commits to the previous entry's hash. Sink and destination:

```jsonc
"transparency": { "audit_sink": "stderr" }               // JSONL on stderr, prefixed AUDIT
"transparency": { "audit_sink": "C:\\ProgramData\\windows-mcp\\audit.jsonl" }  // one appended file
"transparency": { "audit_sink": "C:\\ProgramData\\windows-mcp\\audit\\" }      // directory: one file per session
```

`stderr` is the default. stdout is never used — it belongs to the MCP transport.

A value naming a **directory** (an existing directory, or any path ending in a
separator) switches on per-session mode: each run writes its own
`session-<stamp>.audit.jsonl`, and a shared, hash-chained `audit-manifest.jsonl`
links the session heads. This is the recommended form for a long-lived install.
Because each run writes its own file, a restart no longer restarts the sequence
inside a shared file — the old single-file behaviour appended two runs into one
JSONL, so the second run's `seq` reset to 0 and looked like a break. The `<stamp>`
matches the recording's, so `session-<stamp>.audit.jsonl` and
`session-<stamp>.mp4` name the same session.

### Entry shape

```json
{"seq":2,"timestamp":"2026-07-31T14:27:37.13Z","event":"egress.start",
 "payload":{"enforcement":"proxy-only","listen":"127.0.0.1:8181"},
 "prev_hash":"3cedc78a…","entry_hash":"f296ed3b…"}
```

`seq` starts at 0 and increments by exactly one. `prev_hash` is the previous
entry's `entry_hash`; the first entry's is empty. A gap in `seq`, or a
`prev_hash` that does not match, means the log was truncated or edited.

Tool calls record the tool name and an **argument digest**, never raw arguments —
so the log is safe to ship to a SIEM without leaking what was typed or read.

### Keying the chain

Set `WINDOWS_MCP_AUDIT_KEY` in the server's environment and every entry gains a
`mac` field — an HMAC-SHA256 over its `entry_hash` under that key. The hash chain
proves the log is internally consistent; the MAC proves it was written by a holder
of the key, so an attacker who can write the file cannot forge a valid-looking
chain without also holding the key. The key is an **environment secret, never a
flag or a policy field**: argv is world-readable and the policy is meant to be
reviewed and checked in. With no key set the chain is unkeyed — the default — and
carries no `mac`. Verify a keyed chain by naming the same variable:

```powershell
windows-mcp-server audit verify --key-env WINDOWS_MCP_AUDIT_KEY C:\ProgramData\windows-mcp\audit\
```

### Anchoring the head off-box

Keying still leaves the key on the same machine as the log. Anchoring puts the
chain **head** somewhere the session cannot reach back into, so an on-box adversary
who rewrites the log cannot also rewrite what was already published:

```jsonc
"transparency": { "anchor": { "destination": "eventlog", "cadence": "5m" } }
```

`eventlog` writes the current head (seq + hash) to the Windows Application event
log on each cadence, and also records an `audit.anchor` entry in the chain itself.
It only anchors when the chain advanced, so an idle server does not grow the log.
Anchoring is defence-in-depth and never gates startup: if the event-log source
cannot be opened (it needs elevation to register), it degrades to chain-only
anchoring with a warning. Anchoring is **off by default**.

### Event vocabulary

| Event | When |
|---|---|
| `server.start` | Startup, carrying the server version and the session stamp |
| `server.surface` | The resolved tool surface: persona, enabled toolsets, additional/excluded tools, read-only, credentials-file-present |
| `tools.persona_bypass.denied` | Startup refused: `--tools` named a tool outside the active persona's toolsets |
| `audit.anchor` | The chain head was published off-box (when `transparency.anchor` is set) |
| `devicePolicy.startup` | The startup admission decision |
| `devicePolicy.startup.deny` | Startup refused; the server exits |
| `tools.baseline`, `prompts.baseline`, `resources.baseline`, `discover.baseline` | Rug-pull fingerprints pinned |
| `policy.decision` | Every verdict, including allows, and including audit mode |
| `tool.call`, `resource.read`, `prompt.get` | Requests, with digested arguments |
| `server.discover`, `subscriptions.listen` | Protocol-level events under 2026-07-28 |
| `credentials.installed`, `credentials.removed` | Identifiers only, never secrets |
| `credentials.exposure.denied` | Startup refused: credentials served next to shell/filesystem without acknowledgement |
| `credentials.exposure.acknowledged` | Started with the exposure, acknowledged in policy — the residual risk is recorded |
| `egress.start`, `egress.stop`, `egress.summary` | Proxy lifecycle and periodic counters. The distinct hosts refused this session ride in the `denied_hosts` payload, capped at 50 |
| `egress.enforce.applied`, `egress.enforce.error`, `egress.recovered`, `egress.suspend` | Firewall enforcement lifecycle |
| `rugpull.detected` | A served manifest or the discover advertisement changed after startup |
| `killswitch.trip` | A trigger fired |
| `killswitch.disarmed` | A trigger fired while its policy switch was off — detected and recorded, but nothing was actuated |
| `killaction.done`, `killaction.skip`, `killaction.error` | Each rung of the containment ladder |
| `session.stop` | Graceful stop |
| `heartbeat` | Periodic liveness, so a stall is visible as an absence |

`killswitch.disarmed` is worth watching specifically: it means something the
policy *could* have contained happened, and the policy chose not to.

### Verifying a chain

Use the built-in verb. Given a single session file it verifies that one chain;
given a directory (the directory-mode sink) it verifies the manifest chain, every
session file, and that each sealed session's head matches its manifest record:

```powershell
windows-mcp-server audit verify C:\ProgramData\windows-mcp\audit\
windows-mcp-server audit verify C:\ProgramData\windows-mcp\audit\session-20260803-120000.audit.jsonl
```

It exits non-zero and reports every problem it found — a `seq` gap, a `prev_hash`
that does not chain, an edited payload, a session on disk that the manifest never
recorded, or a sealed session whose head no longer matches. When the sink is
`stderr` there is nothing to verify against later; strip the `AUDIT ` prefix from
each line if you want to feed captured stderr into the same check.

**What the manifest does and does not guarantee.** The manifest makes a *restart*
unable to silently drop history: every run writes an open record before its first
entry, so a session that crashed or was killed still leaves a chained trace where
its seal should be. What it cannot do on its own is defend against an on-box
adversary who deletes the most recent session's trailing seal — that is
indistinguishable from a session still running or just killed. Closing that gap is
what [keying the chain](#keying-the-chain) and [anchoring the
head](#anchoring-the-head-off-box) are for: the MAC stops an attacker forging a
replacement chain without the key, and anchoring stops one quietly rewriting what
was already published. Unkeyed and un-anchored — the default — the chain is
tamper-*evident* against accident and process death, not tamper-*proof* against a
local admin, the same posture the [trust
model](../README.md#trust-model--read-this) states. Keying plus anchoring is what
raises it toward the latter.

### Rotation and retention

The server appends and never rotates. A long-lived deployment should rotate
externally, and **rotation breaks the chain by design**: each file verifies
independently from its own first entry, and continuity across files is something
your collection has to preserve. Keep whole files, and keep the last entry of
the previous file if you need to prove the join.

---

## Related

- [Policy configuration](policy-config.md) — the `transparency` block
- [Security architecture](security-architecture.md) — why these are always on
- [Egress](egress.md) — the counters reported under `server.egress`
