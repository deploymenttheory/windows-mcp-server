# windows-mcp-server

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

> **Safety:** several tools (PowerShell, Registry, FileSystem, Process, App) have
> full system access with no sandboxing. Run in a VM or Windows Sandbox for
> untrusted workloads — see [docs/vm-isolation.md](docs/vm-isolation.md) for the
> isolation options, including disposable, Hyper-V-Manager-invisible **HCS**
> sandboxes.

## Requirements

- Windows 10 or 11 (amd64 or arm64)
- Go 1.25+ to build

## Build & run

```sh
go build -o windows-mcp-server.exe ./cmd/windows-mcp-server
./windows-mcp-server.exe stdio
```

The server speaks MCP over stdio: any MCP-capable client launches the binary
with the `stdio` subcommand. Build it once and point your client at the full
path to `windows-mcp-server.exe`.

Configuration flags (persona, toolsets, read-only, overlay) are passed either as
extra `args` after `stdio`, or as `WINDOWS_MCP_*` environment variables — see
[Flags & environment](#flags--environment). The examples below select the
`first-line-support` persona; drop or change that argument as needed.

## Connecting MCP clients

### Claude Code

Add the server from the CLI (user scope makes it available in every project).
Everything after `--` is the command Claude Code launches:

```sh
claude mcp add windows --scope user -- "C:\path\to\windows-mcp-server.exe" stdio --persona first-line-support
```

Or commit a project-scoped `.mcp.json` at your repo root (Claude Code prompts
once to approve project servers):

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

Verify with `claude mcp list`, and inside a session use `/mcp` to see the
server's tools.

### Cursor

Create `.cursor/mcp.json` in your project (or `%USERPROFILE%\.cursor\mcp.json`
for all projects), then enable the server under **Settings → MCP**:

```json
{
  "mcpServers": {
    "windows": {
      "command": "C:\\path\\to\\windows-mcp-server.exe",
      "args": ["stdio", "--persona", "qa-test-engineer"]
    }
  }
}
```

### Codex CLI

Add it from the CLI (everything after `--` is the server command):

```sh
codex mcp add windows -- "C:\path\to\windows-mcp-server.exe" stdio --persona business-user
```

Or edit `%USERPROFILE%\.codex\config.toml` directly (TOML, one `[mcp_servers.*]`
table per server; a `command` key means a stdio server):

```toml
[mcp_servers.windows]
command = "C:\\path\\to\\windows-mcp-server.exe"
args = ["stdio", "--persona", "business-user"]

# Optional: configure via environment instead of args.
[mcp_servers.windows.env]
WINDOWS_MCP_READ_ONLY = "true"
WINDOWS_MCP_OVERLAY = "true"
```

Use `codex mcp list` to confirm the server is registered.

### Claude Desktop

Add to `claude_desktop_config.json` (Settings → Developer → Edit Config):

```json
{
  "mcpServers": {
    "windows": {
      "command": "C:\\path\\to\\windows-mcp-server.exe",
      "args": ["stdio"]
    }
  }
}
```

> **Path & escaping notes:** use the absolute path to the built `.exe`. In JSON,
> escape backslashes (`C:\\path\\...`); in TOML you may use `\\` or a
> single-quoted literal string (`'C:\path\...'`). If you keep the binary on
> `PATH`, `"windows-mcp-server.exe"` alone also works.

## Tools

Tools are grouped into **toolsets**. The default configuration enables `screen`,
`interaction`, `apps`, and `system`; `shell`, `filesystem`, and `web` are opt-in.

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

The typical loop: call **`Snapshot`** to get the foreground window and a labeled
tree of interactive elements, then act on a label with **`Click`**, **`Type`**,
or **`Scroll`**. Take a fresh `Snapshot` after the UI changes.

## Personas

Personas are curated tooling collections: each selects a toolset combination
(and read-only stance) **and** injects tailored guidance into the server's
instructions so the agent adopts that persona's workflow.

```sh
./windows-mcp-server.exe stdio --persona qa-test-engineer
./windows-mcp-server.exe personas   # list them
```

| Persona | Toolsets | Focus |
|---|---|---|
| `first-line-support` | screen, interaction, apps, system, shell, diagnostics | Diagnose before acting; `SystemInfo`/`Process`/`Service` + PowerShell |
| `qa-test-engineer` | screen, interaction, apps, system, filesystem, web, testing | Deterministic UI tests; label targeting, `Assert`, `CaptureEvidence` |
| `business-user` | screen, interaction, apps, web, testing | End-user tasks & user-journey testing through the real UI; verify with `Assert`/`GetText`; no shell/registry/filesystem |

## User-journey testing (RPA)

The `business-user` and `qa-test-engineer` personas are built for driving
scripted user journeys — open apps, log into sites, click through flows, browse,
check and change settings via the UI — and verifying each step. The loop is:

**perceive → target → act → synchronize → verify**

```
Snapshot                       # see the foreground window + labeled elements
Invoke  {name:"Sign in"}       # act via the accessibility pattern (reliable)
WaitFor {condition:active_window, window_name:"Inbox"}
Assert  {condition:text_present, text:"Welcome"}
CaptureEvidence {label:"logged in"}
```

**Prefer `Invoke` over `Click`/`Type`.** `Invoke` (and `set_value`, `toggle`,
`select`, `expand`/`collapse`) acts on an element through its UI Automation
control pattern instead of synthesizing mouse/keyboard input. It does not depend
on the window being focused, unoccluded, or at a particular DPI, so journeys are
far less flaky. `Click`/`Type` remain as the fallback for controls that expose
no pattern.

**Target by name or by label.** Every interaction tool accepts a `label` from the
latest Snapshot, an explicit `loc` [x,y], or a `name` (with optional
`control_type` and `nth`) — so a step can read as `Invoke {name:"Submit",
control_type:"Button"}`. Use `GetText` to read an element's value for precise
assertions.

### What cannot be automated (by design)

These sit on the Windows **secure desktop**, which no user-session process can
see or drive — a platform security boundary, not a limitation of this server:

- The **Windows sign-in / lock screen** and **UAC elevation prompts**.
- Driving **elevated (admin) apps** from a non-elevated process (UIPI).

Design journeys around this: have the harness deliver an **already-signed-in,
unlocked session** (e.g. configure autologon and keep the machine unlocked), and
**auto-start this server at login** (a scheduled task) so it is present when the
journey begins. "Login/logout" inside a journey then means **application and
website** sign-in (fully supported) and `logoff` — not the OS credential screen.
If a journey must handle admin UI or UAC, relax UAC in the dedicated test VM or
run the server elevated.

## Flags & environment

Every flag has a `WINDOWS_MCP_`-prefixed env var (e.g. `--read-only` ↔
`WINDOWS_MCP_READ_ONLY`).

| Flag | Description |
|---|---|
| `--toolsets` | Comma-separated toolsets to enable (`all`, `default`, or specific IDs) |
| `--tools` | Additionally enable individual tools (bypasses toolset filtering) |
| `--exclude-tools` | Disable specific tools |
| `--read-only` | Expose only read-only tools |
| `--persona` | Select a persona preset |
| `--overlay` | Visual feedback overlays (see below) |
| `--record-dir` | Record the whole session to a video file in this directory (see Session recording) |
| `--record-fps` | Recording frame rate (default 4) |
| `--record-codec` | `h264`/`h265` (via ffmpeg; small files) or `mjpeg` (pure-Go, no dependency) |
| `--security` | Master security switch: enforce pre-flight + force-on all transparency services (see below) |
| `--with-mdm` | Pre-flight: require the device to be MDM-enrolled |
| `--with-logged-on-account` | Pre-flight: require the interactive user to match a regex |
| `--with-user-context` | Pre-flight: require an interactive user (not SYSTEM / Session 0) |
| `--is-not-admin` | Pre-flight: require the interactive user to NOT be a local admin |
| `--run-context` | Expected process context: `user` (default) or `system` |
| `--inflight-interval` | In-flight posture re-evaluation cadence (default 60s; 0 disables drift re-eval) |
| `--inflight-control-dir` | Directory watched for a `kill` sentinel file |
| `--guardrails` | Guardrail mode: `off`, `audit`, `enforce` (forced to enforce by `--security`/pre-flight) |
| `--guardrail` | Additional guardrails to require (repeatable): `id` or `id=arg` |
| `--circuit-breaker` / `--circuit-window` / `--circuit-threshold` | Inline destructive-action circuit breaker + tuning |
| `--with-video-session-recording` | Record the session to a video file in this directory |
| `--with-logging` | Audit-log sink: empty/`stderr` for stderr JSONL, or a file path for hash-chained JSONL |
| `--heartbeat-interval` | Heartbeat cadence written to the audit chain (default 30s) |
| `--guardrails-status-addr` / `--guardrails-status-token` | Loopback HTTP status/may-run endpoint + bearer token |
| `--with-kill-switch` | Arm the kill switch |
| `--kill-on-posture-drift` / `--kill-on-circuit-trip` / `--kill-on-rugpull` / `--kill-on-heartbeat-gap` | Kill triggers (all default on) |
| `--kill-action-isolate` | Kill action: firewall isolate the device (default on; requires elevation) |
| `--kill-action-kill-procs` / `--kill-action-proc-names` | Kill action: terminate named processes (requires elevation) |
| `--kill-action-lock` / `--kill-action-shutdown` / `--kill-action-shutdown-delay` | Kill actions: lock / shut down (requires elevation) |
| `--guardrails-bypass` | Break-glass: skip pre-flight checks (logged) |
| `--enable-tier2` + `--graph-*` / `--remote-policy-token` | Opt into the parked tier-2 remote checks (Graph / may-run PDP) |
| `--log-file` | Write debug logs to a file (stdout is reserved for the transport) |

## Visual feedback overlays

For screen capture and video recording, `--overlay` draws click-through,
top-most overlays so a viewer can see what the automation is doing:

- a **green hue** around the focused window on each `Snapshot`, and
- an **orange flash** at each click point.

Overlays never intercept input or take focus.

## Session recording

For audit and playback, `--record-dir <dir>` records the **entire session** to a
single video file, automatically, for every persona — so all sessions can be
tracked. Recording starts when the server starts and finalizes on shutdown,
producing `<dir>/session-<timestamp>.<ext>` plus a `.jsonl` marker log.

- **Codec** (`--record-codec`): `h264` (default) or `h265` use **ffmpeg** when
  it is on `PATH`, giving small files via temporal compression (H.265 is ~50%
  smaller than H.264). When ffmpeg is not installed, recording transparently
  falls back to a **pure-Go MJPEG-AVI** writer — no dependency, but larger files
  (each frame is an independent JPEG). Set `--record-codec mjpeg` to force it.
- **Frame rate / size**: `--record-fps` (default 4); frames are downscaled to
  1280px wide by default to keep files manageable.
- **Timeline markers**: the `Recording` tool (in the `screen` toolset, so every
  persona has it) reports status and adds labeled markers to the `.jsonl` log —
  call `Recording {mode:mark, label:"step name"}` at each journey step so the
  video timeline aligns with what the agent did.

```sh
windows-mcp-server.exe stdio --persona qa-test-engineer \
  --record-dir C:\sessions --record-codec h265 --record-fps 4
```

## Security — four layers

> 📐 **Full architecture with diagrams:** [docs/security-architecture.md](docs/security-architecture.md)
> (layer overview, startup admission, middleware chain, in-flight monitor, audit
> hash chain, rug-pull detection, and the tiered kill-switch ladder, all in Mermaid).

For managed deployments the server gates and contains itself. Turn the whole
model on with `--security`, then opt into specific checks and kill actions:

```sh
windows-mcp-server.exe stdio --security \
  --with-mdm --is-not-admin --with-logged-on-account "^CONTOSO\\svc-rpa\d+$" \
  --with-logging C:\mcp\audit.jsonl --guardrails-status-addr 127.0.0.1:8177 \
  --guardrails-status-token "$TOKEN" --with-kill-switch --kill-action-isolate
```

`--security` forces enforce mode and force-on the transparency services (audit
log, heartbeat, rug-pull detection, on-screen banner, recording capture). The
model has four layers:

**1 — Pre-flight (must pass before the LLM can do anything).** Opt-in, evaluated
once at startup; a failure refuses to start (exit ≠ 0). `--with-mdm` (device is
MDM-enrolled), `--with-logged-on-account=<regex>` (interactive user matches),
`--with-user-context` (interactive user, not SYSTEM/Session 0), `--is-not-admin`
(user is not a local administrator). Add more with `--guardrail` (repeatable):
`secure-boot`, `tpm-present`, `vbs`/`hvci`/`credential-guard`, `bitlocker`,
`domain-joined`, `os-enterprise-sku`, `device-allowlist=<path>`. Run
`windows-mcp-server check` to evaluate once and print the decision (exit 2 if
not admitted) — a posture dry-run for operators and CI.

**2 — In-flight polling.** Every `--inflight-interval` the posture is
re-evaluated and a `kill` sentinel file (`--inflight-control-dir`) is watched;
the server + device status stay pollable and the agent cannot disable them.

**3 — Guardrails (inline tool-call policy).** `--circuit-breaker` (auto-on in
enforce) runs on every tool call on the receiving path — the agent cannot bypass
it — rate-limiting sensitive tools and tripping on destructive tripwires
(disabling Defender/BitLocker/firewall, clearing MDM enrollment).

**4 — Transparency / always-on (agent cannot switch off).**
- **On-screen security banner** — any security event raises a persistent red
  banner, drawn on-screen and captured by the session recording, so a human sees
  it and it is on the video.
- **Hash-chained audit log** (`--with-logging`) — every action and security
  event is an append-only, tamper-evident entry that commits to the previous
  entry's hash; any edit/insert/delete/reorder breaks the chain. Tool calls log
  the tool name and an **argument digest**, never the raw arguments.
- **Heartbeat** — periodic chained entries so an external watcher (or the
  in-process watchdog) detects a stall.
- **Rug-pull detection** — the tool manifest is fingerprinted at startup; if the
  advertised tools mutate afterwards (added/removed/renamed tools, changed
  descriptions or schemas — a "rug pull"), the served `tools/list` and the
  periodic monitor both catch it and trip the kill switch.

**Kill switch — tiered, out-of-band.** Triggers (`--with-kill-switch`,
`--kill-on-posture-drift`/`-circuit-trip`/`-rugpull`/`-heartbeat-gap`, a sentinel
file, `POST /revoke`, or the `Kill` MCP tool) are configured separately from
actions. On any trip the switch **always** raises the banner, seals the audit
log, finalizes the recording, and aborts the session. Opt-in escalations run in
order: `--kill-action-isolate` (firewall block-all; loopback stays exempt so the
status endpoint survives — default on), `--kill-action-kill-procs`
(`--kill-action-proc-names`), `--kill-action-lock`, `--kill-action-shutdown`.
The **default is isolate + abort, no shutdown.**

**Privilege model — best-effort degrade.** The server runs in the (non-admin)
user context. The elevation-only actions (isolate / kill-procs / shutdown) run
only when the process is actually elevated; otherwise they are skipped and
audited (`killaction.skip … not elevated`) while the banner, log-seal,
recording-finalize, and abort still happen.

### Threats this addresses

- **Dynamic rug pulls** — tool-manifest fingerprint + `tools/list` interception +
  periodic recheck (silent `tools/list_changed` is suppressed).
- **Indirect prompt injection / data-exfil loops** — the circuit breaker escalates
  to network isolation, cutting the exfil channel, then aborts.
- **Out-of-band control** — the status endpoint, audit log, heartbeat, monitor,
  and kill switch are not exposed as tools; the only agent-facing tools are the
  read-only `GuardrailStatus` and the trigger-only `Kill`.

### Trust model — read this

The local pre-flight/posture checks (`dsregcmd`, registry, WMI) are **auditable
defense-in-depth, not a hard boundary** — a local admin can spoof those signals.
The containment layers raise the cost of, and record, in-session compromise but
do not replace the OS controls you already own — pair them with **WDAC/AppLocker**,
Conditional Access, and **code signing**. The authoritative remote tier
(Microsoft Graph device compliance, TPM attestation, external may-run PDP) is
**parked** behind `--enable-tier2` for later re-integration.

## Architecture

```
cmd/windows-mcp-server   Cobra/Viper CLI (stdio transport)
internal/guardrails      admission/runtime policy: decision doc, providers,
                         run-context, circuit breaker, kill switch, status
internal/winmcp          server bootstrap: inventory + MCP server + deps middleware
internal/desktop         the Windows engine — a dedicated COM STA thread serving
                         UIA traversal, SendInput, GDI screenshots, overlays,
                         PowerShell, and a WMI worker thread
pkg/windows              the MCP tool definitions + dependency-injection glue
pkg/inventory            domain-agnostic toolset engine (grouping, filtering,
                         personas, read-only, feature flags)
```

All Win32/COM work is serialized onto one STA thread; WMI runs on its own
thread-affine worker. Tool handlers receive dependencies from the request
context via receiving middleware.

## Development

```sh
go build ./...
go test ./...        # inventory + param tests run everywhere; engine/tool
                     # tests are Windows-only and run on a Windows host
```

The `pkg/inventory` engine and parameter helpers are cross-platform and tested
in CI; the Windows automation packages build and test only on Windows.
