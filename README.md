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
> untrusted workloads.

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
| `--run-context` | Expected process context: `user` (default) or `system` (see Guardrails) |
| `--guardrails` | Admission mode: `off` (default), `audit`, or `enforce` |
| `--enterprise-guardrails` | Alias for `--guardrails=enforce` with the managed-device preset |
| `--guardrail` | Additional guardrails to require (repeatable): `id` or `id=arg` |
| `--guardrails-interval` | Continuous re-evaluation interval (default 60s; 0 disables) |
| `--guardrails-status-addr` | Loopback HTTP address for the status/may-run endpoint |
| `--guardrails-status-token` | Bearer token required by the status endpoint |
| `--guardrails-control-dir` | Directory watched for a `kill` sentinel file |
| `--guardrails-bypass` | Break-glass: skip guardrail checks (logged) |
| `--circuit-breaker` | Inline destructive-action circuit breaker (auto-on in enforce mode) |
| `--graph-tenant` / `--graph-client-id` / `--graph-client-secret` | Entra app credentials for the authoritative Entra + Intune compliance checks (Microsoft Graph) |
| `--remote-policy-token` | Bearer token presented to a `remote-policy=<url>` may-run endpoint |
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

## Enterprise guardrails

For managed deployments the server can gate itself: validate the device and its
run context before serving, keep validating during the session, expose its
posture for polling, and stop itself if things go wrong. It follows a
policy-decision / policy-enforcement split — a runner evaluates pluggable checks
into a single **decision document**, and enforcement points act on it.

```sh
windows-mcp-server.exe stdio --enterprise-guardrails \
  --guardrail domain-joined --guardrails-status-addr 127.0.0.1:8177 \
  --guardrails-status-token "$TOKEN" --guardrails-control-dir C:\mcp\control
```

- **Admission gate.** `--guardrails audit` evaluates and logs but never blocks
  (for rollout); `--guardrails enforce` refuses to start (exit ≠ 0) if a required
  check fails. `--enterprise-guardrails` is enforce + the managed-device preset:
  **MDM-enrolled + Entra-joined + run-context=user** (plus the Graph compliance
  checks below when Graph is configured). Add checks with `--guardrail`
  (repeatable): `domain-joined`, `os-enterprise-sku`, `device-allowlist=C:\allow.txt`,
  `remote-policy=<url>`.
- **Just-in-time device posture (read live from the OS).** These read the
  hardware/OS security state directly at evaluation time — no cache, no cloud, no
  reporting lag — through the win32 and WMI SDKs, and are re-checked by the
  continuous monitor so drift (Secure Boot turned off, VBS stopped, BitLocker
  suspended) trips the kill switch within one interval. Opt in per control with
  `--guardrail`: `secure-boot` (UEFI state from the firmware-backed registry),
  `tpm-present` / `tpm-attestation-capable` (TPM Base Services — unprivileged),
  `vbs` / `hvci` / `credential-guard` (`Win32_DeviceGuard`), `bitlocker`
  (`Win32_EncryptableVolume` — requires elevation; reports rather than silently
  passes when denied), and `tpm-attested` (a **live, nonce-bound TPM platform
  quote** — `NCryptCreateClaim` runs a TPM2_Quote over the PCRs with a fresh
  nonce as qualifying data, signed by a machine-scoped AIK, self-verified with
  `NCryptVerifyClaim`). A platform quote is a machine operation, so the AIK needs
  an elevated/SYSTEM context; without elevation `tpm-attested` degrades to the
  at-source measured-boot TCG log and reports honestly. These are direct
  measurements — the freshest signal available, with no wait on an Intune sync.

  Run `windows-mcp-server check` to evaluate the guardrail set once and print the
  decision document (exit 2 if the device is not admitted) — a posture dry-run for
  operators and CI. Run it elevated to produce and verify the signed TPM quote.
- **Authoritative device compliance (Microsoft Graph).** Supply an Entra app
  registration (`--graph-tenant/--graph-client-id/--graph-client-secret`, app
  permissions `Device.Read.All` + `DeviceManagementManagedDevices.Read.All`) and
  the server verifies **enrollment and compliance in both Entra and Intune** via
  Graph (the beta endpoint, for the richer managed-device and attestation
  fields): `graph-entra-registered`, `graph-entra-compliant`,
  `graph-intune-enrolled`, `graph-intune-compliant`, and `graph-attested`
  (Intune's reported Device Health Attestation). Intune's copy is authoritative
  but lags a sync; the JIT posture checks above read the same underlying state
  live. Compliance/enrollment checks join the enterprise preset automatically;
  the device is keyed by its Entra device ID (from `dsregcmd`). Prefer supplying
  the secret via the environment (`WINDOWS_MCP_GRAPH_CLIENT_SECRET`).
- **Remote may-run policy.** `--guardrail remote-policy=<url>` POSTs a small
  `{device, run_context}` request to an external PDP and honors its response —
  both a flat `{"allow":true}` and an OPA-style `{"result":{"allow":true}}`
  document. A deny flips admit, and via continuous verification trips the kill
  switch. `--remote-policy-token` sets the bearer token.
- **Run context.** `--run-context user` (default) is validated against the
  process token. `--run-context system` is auto-limited: desktop-automation
  toolsets are disabled (Session 0 cannot drive the interactive desktop) and a
  notification is shown — it becomes a diagnostics/guardrail daemon. Personas
  always require user context.
- **Continuous verification.** Every `--guardrails-interval` the posture is
  re-checked; if a previously-passing check now fails (e.g. MDM removed) the
  session self-terminates.
- **Circuit breaker.** With `--circuit-breaker` (auto-on in enforce mode) an
  inline policy runs on every tool call: it rate-limits sensitive tools and
  trips on destructive tripwires (disabling Defender/BitLocker/firewall, clearing
  MDM). It runs on the receiving path, independent of the agent, so the LLM
  cannot bypass it.
- **Kill switch.** The session can be stopped out-of-band — by posture drift, a
  `kill` file in `--guardrails-control-dir`, `POST /revoke` on the status
  endpoint, or the `Kill` MCP tool. A kill finalizes the recording and logs the
  reason. The authoritative triggers are independent of the agent.
- **Status / may-run.** The `GuardrailStatus` MCP tool (always available) and the
  loopback HTTP endpoint (`GET /guardrails`, bearer-token) return the decision
  document — this is the "may-run" response an orchestrator can poll.

### Trust model — read this

The **tier-1 local** guardrails (`dsregcmd`, registry, WMI) are **auditable
defense-in-depth, not a hard security boundary** — a local admin can spoof those
signals and unhook endpoint protection. The **authoritative tier-2** checks are
remote and TPM-rooted: the Graph `graph-intune-compliant` / `graph-entra-compliant`
/ `graph-attested` providers read Intune device compliance and Device Health
Attestation (which a local admin cannot forge), and `remote-policy` defers to an
external PDP. Configure the Graph credentials (and/or a may-run endpoint) for a
real boundary — the local checks alone only raise the bar. Either way, pair the
guardrails with the OS controls you already own — **WDAC/AppLocker**, Conditional
Access, and **code signing**. The circuit breaker and kill switch contain
in-session compromise; they do not replace those controls.

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
