# windows-mcp-server

[![MCP conformance](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fdeploymenttheory%2Fwindows-mcp-server%2Fmain%2Fconformance%2Fbadge.json)](docs/mcp-compliance.md)
[![Spec compliance](https://github.com/deploymenttheory/windows-mcp-server/actions/workflows/mcp-spec-compliance.yml/badge.svg)](https://github.com/deploymenttheory/windows-mcp-server/actions/workflows/mcp-spec-compliance.yml)

A [Model Context Protocol](https://modelcontextprotocol.io) server that bridges
AI agents to the **Windows desktop** — UI Automation, synthetic mouse/keyboard
input, screenshots, window and application control, PowerShell, the registry,
processes, the filesystem, and web scraping.

It is a Go port of the Python [Windows-MCP](https://github.com/CursorTouch/Windows-MCP)
project, built on the [`go-bindings-win32`](https://github.com/deploymenttheory/go-bindings-win32)
and [`go-bindings-wmi`](https://github.com/deploymenttheory/go-bindings-wmi) SDKs
and the official [MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk). No
computer-vision model is required: the agent perceives the UI through the
Windows accessibility tree.

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

---

## Features

| | What it does | Guide |
|---|---|---|
| **Desktop automation** | 28 tools across 10 toolsets: accessibility-tree perception, UI Automation pattern invocation, synthetic input, screenshots, apps, windows, PowerShell, registry, filesystem, processes, services, scraping | [Toolsets and personas](docs/toolsets-and-personas.md) |
| **Personas** | Presets that select toolsets *and* inject workflow guidance, so the agent adopts a role rather than just getting a tool list | [Toolsets and personas](docs/toolsets-and-personas.md#personas) |
| **Device policy engine** | Gate every call on live device posture — MDM enrolment, Entra join, Secure Boot, BitLocker, VBS/HVCI, TPM attestation. Rules match by tool, toolset or annotation, so a screenshot is not gated like a shell command | [Policy configuration](docs/policy-config.md) |
| **Egress allowlist** | Declare the domains the device may reach. A loopback proxy enforces it, optionally backed by firewall rules so named applications — or the whole machine — cannot go around it | [Egress setup](docs/egress.md) |
| **Credentials** | The agent signs in to apps and sites without ever being told the secret. No mode returns plaintext | [Credentials](docs/credentials.md) |
| **Session recording** | Once `transparency.recording_dir` is set, the whole session goes to one video file — automatically, under every persona — with timeline markers | [Session recording](docs/recording.md) |
| **Transparency** | Hash-chained audit log, heartbeat, rug-pull detection, on-screen security banner. The agent cannot switch any of it off | [Monitoring](docs/monitoring.md) |
| **Kill switch** | Out-of-band, tiered containment. A trip always audits, raises the banner and seals the log; the optional rungs — isolate, kill processes, lock, shut down — run in a fixed order, with the recording finalized before shutdown and the session aborted last | [Security architecture](docs/security-architecture.md) |
| **MCP conformance** | Protocol revision `2026-07-28`, measured by the official suite in CI | [MCP compliance](docs/mcp-compliance.md) |

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

Some settings are environment-only, because they are secrets and `argv` is
world-readable: `WINDOWS_MCP_GRAPH_TENANT`, `WINDOWS_MCP_GRAPH_CLIENT_ID`,
`WINDOWS_MCP_GRAPH_CLIENT_SECRET`, `WINDOWS_MCP_REMOTE_POLICY_TOKEN`, and
whatever variable `egress.auth_token_env` names.

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
    audit                hash chain, sink, VerifyChain
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
