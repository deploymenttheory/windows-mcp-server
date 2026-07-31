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
"transparency": { "audit_sink": "stderr" }              // JSONL on stderr, prefixed AUDIT
"transparency": { "audit_sink": "C:\\ProgramData\\windows-mcp\\audit.jsonl" }
```

`stderr` is the default. stdout is never used — it belongs to the MCP transport.

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

### Event vocabulary

| Event | When |
|---|---|
| `server.start` | Startup, carrying the server version |
| `devicePolicy.startup` | The startup admission decision |
| `devicePolicy.startup.deny` | Startup refused; the server exits |
| `tools.baseline`, `prompts.baseline`, `resources.baseline`, `discover.baseline` | Rug-pull fingerprints pinned |
| `policy.decision` | Every verdict, including allows, and including audit mode |
| `tool.call`, `resource.read`, `prompt.get` | Requests, with digested arguments |
| `server.discover`, `subscriptions.listen` | Protocol-level events under 2026-07-28 |
| `credentials.installed`, `credentials.removed` | Identifiers only, never secrets |
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

There is no CLI verb for this yet — `VerifyChain` is a Go API, and because it
lives under `internal/`, the checker has to live **inside this repository**. Drop
this in as `cmd/verify-audit/main.go` and `go run ./cmd/verify-audit <file>`:

```go
package main

import (
	"bufio"; "encoding/json"; "fmt"; "os"

	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/audit"
)

func main() {
	f, _ := os.Open(os.Args[1])
	defer f.Close()
	var entries []audit.AuditEntry
	s := bufio.NewScanner(f)
	for s.Scan() {
		var e audit.AuditEntry
		if err := json.Unmarshal(s.Bytes(), &e); err == nil {
			entries = append(entries, e)
		}
	}
	if err := audit.VerifyChain(entries); err != nil {
		fmt.Println("chain broken:", err)
		os.Exit(1)
	}
	fmt.Printf("%d entries verified\n", len(entries))
}
```

When the sink is `stderr`, strip the `AUDIT ` prefix first — the rest of each
line is the JSON object.

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
