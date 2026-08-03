# windows-mcp-server

[![MCP conformance](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fdeploymenttheory%2Fwindows-mcp-server%2Fmain%2Fconformance%2Fbadge.json)](docs/mcp-compliance.md)
[![Spec compliance](https://github.com/deploymenttheory/windows-mcp-server/actions/workflows/mcp-spec-compliance.yml/badge.svg)](https://github.com/deploymenttheory/windows-mcp-server/actions/workflows/mcp-spec-compliance.yml)

A [Model Context Protocol](https://modelcontextprotocol.io) server that bridges
AI agents to the **Windows desktop** — UI Automation, synthetic mouse/keyboard
input, screenshots, window and application control, PowerShell, the registry,
processes, the filesystem, and web scraping. No computer-vision model is required:
the agent perceives the UI through the Windows accessibility tree.

What separates it from a plain automation bridge is that it is the only Windows
MCP server that **gates every agent action on live device posture** and
**constrains the agent's network egress**, and records both in a tamper-evident
audit chain the agent cannot switch off. It turns an agent with system access into
an agent whose actions are conditional, bounded, and reviewable.

- **Device policy engine** — every tool call, resource read and prompt fetch is
  evaluated against live device signals (MDM enrolment, Entra join, Secure Boot,
  BitLocker, VBS/HVCI, TPM attestation) before it runs, and refused, warned or
  contained by policy configuration. Rules match by tool, toolset or annotation, so
  a screenshot is not gated like a shell command. → [Policy configuration](docs/policy-config.md)
- **Egress allowlist** — a loopback proxy admits only the domains you declare,
  checking the allowlist before it resolves a name, optionally backed by firewall
  rules so named applications — or the whole machine — cannot go around it.
  → [Egress setup](docs/egress.md)
- **Tamper-evident transparency** — a hash-chained audit log (optionally keyed
  and anchored off-box), heartbeat, rug-pull detection, whole-session recording,
  and an out-of-band tiered kill switch. None of it is agent-disableable.
  → [Monitoring](docs/monitoring.md) · [Security architecture](docs/security-architecture.md)

> **Several tools (PowerShell, Registry, FileSystem, Process, App) have full
> system access with no sandboxing.** That is the design, not an oversight. Run
> untrusted workloads in a VM or Windows Sandbox — see
> [VM isolation](docs/vm-isolation.md) — and see [SECURITY.md](SECURITY.md) for
> what is and is not in scope as a vulnerability.

---

## Quick start

Windows 10 or 11 (amd64 or arm64), Go 1.25+ to build.

```powershell
go build -o windows-mcp-server.exe ./cmd/windows-mcp-server
```

Point any MCP client at the binary with the `stdio` subcommand:

```json
{
  "mcpServers": {
    "windows": {
      "command": "C:\\path\\to\\windows-mcp-server.exe",
      "args": ["stdio", "--persona", "first-line-support"]
    }
  }
}
```

**→ [Getting started](docs/getting-started.md)** covers Claude Code, Cursor,
Codex CLI and Claude Desktop specifically, and what to do before pointing this at
a machine you care about.

Not sure this is for you? If you have to **approve** it on a fleet, read
[Deciding to deploy this](docs/deployment-decision.md). If you have a **job to
do**, see the walk-throughs for a
[UI regression suite](docs/use-case-ui-regression.md) or a
[first-line support queue](docs/use-case-first-line-support.md).

---

## Features

| | What it does | Guide |
|---|---|---|
| **Desktop automation** | 30 tools across 11 toolsets: accessibility-tree perception, UI Automation pattern invocation, synthetic input, screenshots, apps, windows, PowerShell, registry, filesystem, processes, services, scraping, plan-and-apply | [Toolsets and personas](docs/toolsets-and-personas.md) |
| **Personas** | Presets that select toolsets *and* inject workflow guidance, so the agent adopts a role rather than just getting a tool list | [Toolsets and personas](docs/toolsets-and-personas.md#personas) |
| **Credentials** | The agent signs in to apps and sites without ever being told the secret. The `Credentials` tool has no read mode and no engine method returns plaintext — but see the note below on toolset exposure | [Credentials](docs/credentials.md) |
| **Session recording** | Once `transparency.recording_dir` is set, the whole session goes to one video file — automatically, under every persona — with timeline markers | [Session recording](docs/recording.md) |
| **Kill switch** | Out-of-band, tiered containment. A trip always audits, raises the banner and seals the log; the optional rungs — isolate, kill processes, lock, shut down — run in a fixed order, with the recording finalized before shutdown and the session aborted last | [Security architecture](docs/security-architecture.md) |
| **MCP conformance** | Protocol revision `2026-07-28`, measured by the official suite in CI | [MCP compliance](docs/mcp-compliance.md) |

> **On the credentials claim:** the guarantee holds at the tool boundary — the
> `Credentials` tool cannot read a secret back and no engine method returns one.
> Another toolset could once route around it: installed generic credentials
> live in the calling user's Credential Manager, so a persona that also carries
> `shell` (which can `CredRead`) or `filesystem` (which can read a Credential
> Manager backup) could retrieve them another way. The server now **refuses to
> start** when `--credentials-file` is combined with either toolset, unless the
> policy document acknowledges the exposure
> (`credentials.acknowledge_toolset_exposure`), and audits the decision — so the
> exposure is a deliberate, recorded choice rather than a silent hole. See the
> [trust model](#trust-model--read-this).

---

## Tools

Tools are grouped into **toolsets**. `screen`, `interaction`, `apps` and `system`
are on by default; the rest are opt-in.

| Toolset | Default | Tools |
|---|:---:|---|
| `screen` | ✓ | `Snapshot`, `Screenshot`, `DisplayInventory`, `Recording` |
| `interaction` | ✓ | `Click`, `Type`, `Invoke`, `GetText`, `Scroll`, `Move`, `Shortcut`, `Wait`, `WaitFor`, `MultiSelect`, `MultiEdit` |
| `apps` | ✓ | `App` (launch / launch_executable / switch / resize) |
| `system` | ✓ | `Clipboard`, `Process`, `Registry`, `Notification` |
| `shell` | | `PowerShell` |
| `filesystem` | | `FileSystem` (read / write / copy / move / delete / list / search / info) |
| `web` | | `Scrape` |
| `diagnostics` | | `SystemInfo` (OS/hardware/disk via WMI), `Service` (list / start / stop / restart) |
| `testing` | | `Assert` (PASS/FAIL UI condition), `CaptureEvidence` (screenshot + tree) |
| `planning` | | `Plan`, `Apply` — propose a whole sequence, adjudicate it up front, then run it verbatim — see [Plan and apply](docs/plan-and-apply.md) |
| `credentials` | | `Credentials` (list / verify / inject) — enabled automatically by `--credentials-file` |

Two more are served under every persona and belong to no toolset:
**`GuardrailStatus`** (read-only posture) and **`Kill`** (stop the session).

The typical loop: call **`Snapshot`** for the foreground window and a labeled
tree of interactive elements, then act on a label with **`Invoke`**, **`Click`**
or **`Type`**. Take a fresh `Snapshot` after the UI changes.

### Resources and prompts

| Resource URI | Contents | Toolset |
|---|---|---|
| `windows://desktop/snapshot` | The most recent `Snapshot` — reading it does *not* capture a new one | screen |
| `windows://desktop/displays` | Connected displays: bounds, work area, DPI, scale | screen |
| `windows://session/recording` | Session-recording status, paths, frame count | screen |
| `windows://system/info` | OS, hardware, memory and disk inventory | diagnostics |

| Prompt | Purpose | Toolset |
|---|---|---|
| `rpa-journey` | Drive a scripted end-user journey, verifying each step | interaction |
| `triage-support-issue` | Diagnose a reported problem, gathering state before acting | diagnostics |
| `capture-evidence` | Record reproducible evidence for a test or support case | testing |

**Resources and prompts are filtered by toolset like tools are**, so a prompt
whose toolset is disabled is not served. Prompts build their text from the
matching persona's instructions rather than restating it, so `--persona` and the
prompts cannot drift apart.

Both are decided by the policy engine: `resources/read` and `prompts/get` are
written to the audit log, covered by any rule matching `toolset: "*"` or
`annotation: read-only`, and fingerprinted for rug-pull detection.

---

## Personas

```powershell
.\windows-mcp-server.exe personas                   # list them
.\windows-mcp-server.exe stdio --persona qa-test-engineer
```

| Persona | Toolsets | Focus |
|---|---|---|
| `first-line-support` | screen, interaction, apps, system, shell, diagnostics | Diagnose before acting; `SystemInfo`/`Process`/`Service` + PowerShell |
| `qa-test-engineer` | screen, interaction, apps, system, filesystem, web, testing | Deterministic UI tests; label targeting, `Assert`, `CaptureEvidence` |
| `business-user` | screen, interaction, apps, web, testing | End-user tasks and journey testing through the real UI; no shell, registry or filesystem |

---

## User-journey testing (RPA)

`business-user` and `qa-test-engineer` are built for driving scripted journeys —
open apps, sign into sites, click through flows, check and change settings via
the UI — and verifying each step:

**perceive → target → act → synchronize → verify**

```
Snapshot                       # the foreground window + labeled elements
Invoke  {name:"Sign in"}       # act via the accessibility pattern (reliable)
WaitFor {condition:active_window, window_name:"Inbox"}
Assert  {condition:text_present, text:"Welcome"}
CaptureEvidence {label:"logged in"}
```

**Prefer `Invoke` over `Click`/`Type`.** `Invoke` (and `set_value`, `toggle`,
`select`, `expand`/`collapse`) acts through a UI Automation control pattern
rather than synthesizing input, so it does not depend on the window being
focused, unoccluded or at a particular DPI. Journeys are far less flaky.
`Click`/`Type` remain the fallback for controls exposing no pattern.

**Target by name or label.** The targeting tools accept a `label` from the latest
Snapshot, or a `name` with optional `control_type` and `nth` — so a step reads as
`Invoke {name:"Submit", control_type:"Button"}`. `Click`, `Type` and `Move` also
accept an explicit `loc` [x,y]; `Invoke` and `GetText` resolve through the
accessibility tree and need a `label` or a `name`.

### What cannot be automated, by design

These sit on the Windows **secure desktop**, which no user-session process can
see or drive — a platform boundary, not a limitation of this server:

- The **sign-in / lock screen** and **UAC elevation prompts**
- Driving **elevated apps** from a non-elevated process (UIPI)

Design around it: have the harness deliver an already-signed-in, unlocked
session, and auto-start the server at logon. "Login" inside a journey then means
**application and website** sign-in, which is fully supported. See
[Deployment](docs/deployment.md#running-at-logon).

---

## Security

> 📐 **Architecture with diagrams:** [docs/security-architecture.md](docs/security-architecture.md)
> 📄 **Schema reference:** [docs/policy-config.md](docs/policy-config.md)

A policy engine sits between the MCP caller and the tools. Before a tool runs, a
resource is read or a prompt is fetched, it evaluates device signals against
rules in a policy document and decides what happens.

```
MCP client ──▶ audit ──▶ rug-pull ──▶ policy engine ──▶ tool handler
                                            │
                                      device signals
```

```powershell
.\windows-mcp-server.exe stdio --policy-config C:\ProgramData\windows-mcp\policy.json
```

**With no `--policy-config` the built-in default applies**: the engine is
present, every declared signal is evaluated and every verdict recorded, and
nothing is refused. Adopting the engine cannot break a working deployment before
its policy is written.

| `on_fail` | Effect |
|---|---|
| `allow` | Proceeds; the failure is still recorded |
| `warn` | Proceeds, and the warning rides back with the result so the model sees it |
| `deny` | This call is refused, and re-evaluated next time — a signal that recovers restores service with no restart |
| `kill` | The kill switch trips and the containment ladder runs |

Rules match on tool, toolset or MCP annotation, so a screenshot is not gated on
the posture a shell command is gated on:

```jsonc
{
  "rules": [
    { "name": "baseline",    "match": { "toolset": "*" },              "require": ["run-context"],  "on_fail": "deny" },
    { "name": "destructive", "match": { "annotation": "destructive" }, "require": ["bitlocker"],    "on_fail": "deny" },
    { "name": "shell",       "match": { "tool": "PowerShell" },        "require": ["mdm-enrolled"], "on_fail": "kill" }
  ]
}
```

Requirements are the union across matching rules, so adding a rule never drops
one. Severity is attributed per signal to the most specific rule requiring it:
tool > annotation > named toolset > `"*"`.

```powershell
.\windows-mcp-server.exe policy validate --policy-config policy.json  # document + signal ids; exits 1
.\windows-mcp-server.exe policy check    --policy-config policy.json  # this device now; exits 2 if not admitted
.\windows-mcp-server.exe policy explain  --policy-config policy.json --tool PowerShell
```

Five starting points ship in `policy/examples/`: `audit.json` (adopt first —
refuses nothing), `secure.json`, `enterprise.json`, `locked-down.json` and
`egress.json`.

### Trust model — read this

The local device signals (`dsregcmd`, registry, WMI) are **auditable
defense-in-depth, not a hard boundary** — a local admin can spoof them. The
containment layers raise the cost of, and record, in-session compromise but do
not replace the OS controls you already own: pair them with **WDAC/AppLocker**,
Conditional Access and **code signing**. The authoritative remote signals
(Microsoft Graph, an external may-run endpoint) register only when their
credentials are present — see [Remote signals](docs/remote-signals.md).

### Threat model

What each actor can do, what constrains them, and what is left over. The honest
column is the last one: several controls raise cost and produce evidence rather
than prevent, and this is the register a risk function should read it in. The
[security architecture](docs/security-architecture.md#threat-model-mapping) maps
these to mechanisms.

| Actor | Capability | Control | Residual risk |
|---|---|---|---|
| **Prompt-injected agent** — the model, driven by hostile content | Issue any tool call the served surface allows | Policy engine gates every call on device posture; rate limits break exfil loops; the egress allowlist bounds network reach; the audit chain records every call with argument digests. **Plan-and-apply** adjudicates a whole proposed sequence up front, and `require_plan` can force named or destructive tools through that review | Benign-annotated calls can still **compose** into a harmful outcome when they run one at a time outside a plan; scope the surface with personas, gate destructive annotations, and use `require_plan` where the composition risk is real |
| **Malicious MCP client** — the host process on the other end of stdio | Swap the tool manifest after approval; probe methods | Manifest fingerprinted at startup; `tools/list` and discover intercepted; rug-pull monitor trips the kill switch on drift; `list_changed` suppressed | The stdio transport assumes a trusted host: a client that never drifts is trusted by construction. There is no network listener to attack |
| **Local user** — non-admin, same session | Read what the agent reads; use the running server | Credentials never returned to the model; the `FileSystem` tool refuses the credentials file, the audit log and the policy document; `GuardrailStatus`/`Kill` cannot be removed | A user already holds their own privileges; the server does not raise them. The `Registry` tool is in the default `system` toolset and reads arbitrary keys — gate it with `tool: Registry` if that surface is unwanted |
| **Local administrator** | Spoof device signals; edit the audit log; disable transparency | Local signals are defense-in-depth, not a boundary; the audit chain is tamper-evident, and keying + off-box anchoring raise the bar; pair with WDAC/AppLocker and Conditional Access | An admin can defeat any on-box control — the value is **evidence that survives**, not prevention. The audit HMAC key sits on the box unless anchored off it; path protection matches by cleaned path, not 8.3 names or hard links |
| **Network attacker** | Reach the server; intercept egress | No inbound listener — the transport is stdio only; the egress proxy checks the allowlist before any DNS query and re-checks resolved addresses against loopback/RFC1918/link-local before dialling | Enforce HTTPS and the egress proxy do not intercept navigation **inside an already-open browser**; the `proxy-only` enforcement tier is advisory until backed by firewall rules |

---

## Egress: the domains the device may reach

Declare an allowlist and everything else is dropped:

```jsonc
"egress": {
  "enabled": true,
  "allow": ["*.contoso.com", "login.microsoftonline.com"],
  "allow_ports": [443]
}
```

A loopback CONNECT/HTTP proxy enforces it. `*.contoso.com` covers the apex and
every depth below it, anchored at a label boundary so `fakecontoso.com` never
matches. The allowlist is checked **before** the name is resolved — a refused
host emits no DNS query — and resolved addresses are re-checked against
loopback, RFC1918 and link-local ranges before anything is dialled, so an
allowed name cannot be pointed at something internal. TLS is never intercepted;
there is no CA and nothing is decrypted.

Three enforcement tiers:

| Tier | What forces traffic through the proxy |
|---|---|
| `proxy-only` | Nothing — it constrains whatever is configured to use it. No elevation |
| `scoped` | Outbound-block firewall rules on named applications. Loopback stays reachable, so the proxy is their only route out |
| `global` | The machine's default outbound action becomes block, with a service-scoped exception set for DNS, DHCP, NCSI, time, update and revocation |

Both firewall tiers need elevation and **refuse to start without it** rather than
serving a weaker posture than the document describes.

**→ [Egress setup](docs/egress.md)** — per-tier procedure, browser configuration,
verification and recovery.

---

## Flags and environment

Every flag has a `WINDOWS_MCP_`-prefixed environment variable (`--read-only` ↔
`WINDOWS_MCP_READ_ONLY`).

| Flag | Description |
|---|---|
| `--policy-config` | Path to the device-policy JSON document. Omit for the built-in default |
| `--toolsets` | Comma-separated toolsets to enable (`all`, `default`, or specific ids) |
| `--tools` | Additionally enable individual tools (bypasses toolset filtering) |
| `--exclude-tools` | Disable specific tools; applied last |
| `--read-only` | Expose only read-only tools |
| `--persona` | Select a persona preset |
| `--overlay` | Visual feedback overlays (see below) |
| `--record-fps` | Recording frame rate (default 4) |
| `--record-codec` | `h264`/`h265` (via ffmpeg; small files) or `mjpeg` (pure-Go, no dependency) |
| `--credentials-file` | JSON file of credentials to install at init |
| `--log-file` | Write debug logs to a file (stdout is reserved for the transport) |

### Secrets in the environment

Key material and credentials are **environment-only**, never flags or the policy
document — `argv` is world-readable and the policy is meant to be reviewed and
checked in. The suffix says how the value is delivered:

- **`…_KEY` / `…_TOKEN` / `…_SECRET` / `…_HEADERS`** hold the value **inline**.
- **`…_KEY_FILE`** holds a **path** to a file whose contents are the material —
  used where the material is a key file with its own ACLs (the ed25519 evidence
  signing seed), so it never sits in the process environment.

| Variable | Delivery | Purpose |
|---|---|---|
| `WINDOWS_MCP_AUDIT_KEY` | value | HMAC key that seals the audit chain (absent → unkeyed) |
| `WINDOWS_MCP_APPROVAL_KEY` | value | HMAC key signing dual-control webhook requests |
| `WINDOWS_MCP_EVIDENCE_KEY_FILE` | **path** | ed25519 seed that signs evidence bundles |
| `WINDOWS_MCP_OTLP_HEADERS` | value | `k=v,k=v` auth headers for the OTLP collector |
| `WINDOWS_MCP_GRAPH_TENANT` / `_CLIENT_ID` / `_CLIENT_SECRET` | value | Graph/Intune tier-2 signal credentials |
| `WINDOWS_MCP_REMOTE_POLICY_TOKEN` | value | bearer token for the remote may-run endpoint |
| whatever `egress.auth_token_env` names | value | `Proxy-Authorization` secret the egress proxy requires |

**Everything the security subsystem does** — which signals are read and how
often, which rules cover which tools, what a failure does, what trips the kill
switch and what it actuates, where the audit chain goes, whether the session is
recorded, which domains are reachable — is configured in the policy document
rather than by flags. The questions are relational, and a flag cannot express a
relation: "PowerShell requires MDM enrolment but taking a screenshot does not"
has no spelling as a set of booleans.
[docs/policy-config.md](docs/policy-config.md) carries a table mapping each
removed flag to its field.

### Running as SYSTEM

Session 0 has no desktop to drive, so if the server detects it is running as
SYSTEM the desktop-automation toolsets are dropped and the selection is replaced
with `system, shell, filesystem, diagnostics, web`. This is detected, not
declared. **A persona explicitly requested under SYSTEM is refused** — the server
exits rather than serving a reshaped version of it.

---

## Visual feedback overlays

`--overlay` draws click-through, top-most overlays so a viewer can see what the
automation is doing — a **green hue** around the focused window on each
`Snapshot`, and an **orange flash** at each click point. They never intercept
input or take focus.

---

## MCP conformance

The server targets protocol revision **`2026-07-28`**. Conformance is measured by
the official
[modelcontextprotocol/conformance](https://github.com/modelcontextprotocol/conformance)
suite, which `.github/workflows/mcp-spec-compliance.yml` runs and commits the
results of.

`2026-07-28` is a stateless protocol: no sessions and no `initialize` handshake.
Each request carries its protocol version and client capabilities in `_meta`,
`server/discover` advertises identity and capabilities, `subscriptions/listen`
carries server-to-client notifications, every result carries `resultType`, list
and read results carry `ttlMs` and `cacheScope`, POSTs carry `Mcp-Method` /
`Mcp-Name` headers, and MCP error codes sit in the reserved `-32020..-32099`
range.

Three passes run: **product** (the manifest the server ships), **fixtures** (the
same server with the suite's named fixture tools registered, behind the
`conformance` build tag), and a **backward-compatibility** run at `2025-11-25`.
CI gates on the suite's own exit code — a failure absent from the baseline fails
the build, and so does a baseline entry that has started passing.

`go build ./...` does not compile the conformance host, so **the released binary
has no HTTP listener** and is stdio-only. Both it and `stdio` build their MCP
surface through one function, so what the suite measures is what the shipped
binary serves.

**→ [The report](docs/mcp-compliance.md)** is the verdict; the badge is a
summary of the product pass.

---

## Architecture

```
cmd/windows-mcp-server   Cobra/Viper CLI (stdio transport)
internal/winmcp          server bootstrap: inventory + MCP server + deps middleware
internal/desktop         the Windows engine — one COM STA thread serving UIA
                         traversal, SendInput, GDI screenshots, overlays,
                         PowerShell, plus a WMI worker thread
internal/guardrails/     the security stack, split by lifecycle layer:
    signals              signal vocabulary, probes, registry, checks
    audit                hash chain, destination, VerifyChain
    hostmatch            egress allowlist matching + forbidden address ranges
    policy               document schema, signal cache, engine, verdict
    egress               the egress proxy + Windows firewall enforcement
    enforce              the MCP middleware
    watch                heartbeat, rug-pull, in-flight monitor
    contain              kill switch, containment ladder, actuator, firewall
    status               status endpoint, GuardrailStatus + Kill tools
internal/mcpspec         vendored-schema loader + offline wire validation
internal/mcpconf         official conformance-suite results: ingest + reporting
pkg/windows              MCP tool definitions, personas, dependency-injection glue
pkg/inventory            domain-agnostic toolset engine (grouping, filtering,
                         read-only, resources, prompts)
policy/examples          starting-point policy documents
schema/                  vendored MCP protocol schemas, one dir per revision
conformance/             expected-failure baselines + committed suite results
```

All Win32/COM work is serialized onto one STA thread; WMI runs on its own
thread-affine worker. Tool handlers receive dependencies from the request context
via receiving middleware.

---

## Development

```powershell
go build ./...
go vet ./...
go test ./... -count=1
golangci-lint run --config=./.golangci.yml
```

`pkg/inventory`, the parameter helpers, the policy engine and the egress matcher
are cross-platform and tested everywhere; the Windows automation packages build
and test only on Windows. See [CONTRIBUTING.md](CONTRIBUTING.md) and
[CLAUDE.md](CLAUDE.md).

---

## Documentation

**[docs/](docs/README.md)** — setup and configuration guides, plus the security
architecture and conformance report.

---

## Credits

The tool surface began as a Go port of the Python
[Windows-MCP](https://github.com/CursorTouch/Windows-MCP) project. It is built on
the [`go-bindings-win32`](https://github.com/deploymenttheory/go-bindings-win32)
and [`go-bindings-wmi`](https://github.com/deploymenttheory/go-bindings-wmi) SDKs
and the official [MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk).
