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

## Safety

> **Several tools (PowerShell, Registry, FileSystem, Process, App) have full
> system access with no sandboxing.** Run in a VM or Windows Sandbox for
> untrusted workloads — see [docs/vm-isolation.md](docs/vm-isolation.md) for the
> isolation options, including disposable, Hyper-V-Manager-invisible **HCS**
> sandboxes.

This is the design, not an oversight; see
[SECURITY.md](SECURITY.md) for what is and is not in scope as a vulnerability,
and [Security — four layers](#security--four-layers) for the in-process controls.

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

Subcommands: `stdio` (run the server), `check` (evaluate device guardrails once
and print the decision), `personas` (list the presets), and `spec-check` (score
the served MCP surface against the published protocol schemas).

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
`interaction`, `apps`, and `system`; `shell`, `filesystem`, `web`, `diagnostics`,
`testing`, and `credentials` are opt-in.

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
| `credentials` | | `Credentials` (list / verify / inject) — enabled automatically with `--credentials-file` |

The typical loop: call **`Snapshot`** to get the foreground window and a labeled
tree of interactive elements, then act on a label with **`Click`**, **`Type`**,
or **`Scroll`**. Take a fresh `Snapshot` after the UI changes.

### Resources and prompts

Alongside tools the server exposes read-only **resources** and workflow
**prompts**:

| Resource URI | Contents |
|---|---|
| `windows://desktop/snapshot` | The most recent `Snapshot` — reading it does *not* capture a new one |
| `windows://desktop/displays` | Connected displays: bounds, work area, DPI, scale |
| `windows://session/recording` | Session-recording status, paths, frame count |
| `windows://system/info` | OS, hardware, memory and disk inventory |

| Prompt | Purpose |
|---|---|
| `rpa-journey` | Drive a scripted end-user journey, verifying each step |
| `triage-support-issue` | Diagnose a reported problem, gathering state before acting |
| `capture-evidence` | Record reproducible evidence for a test or support case |

Prompts build their text from the matching persona's instructions rather than
restating it, so `--persona` and the prompts cannot drift apart. Argument values
are completable via `completion/complete` (persona, toolset, tool, app and
credential *names* — never secrets).

Resources and prompts are covered by the same guardrails as tools: `resources/read`
and `prompts/get` are written to the hash-chained audit log, `resources/read` is
rate-limited by the circuit breaker, and both manifests are fingerprinted for
rug-pull detection.

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
| `--credentials-file` | JSON file of credentials to install into the Windows Credential Manager at init (see Credentials) |
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
| `--enforce-https` | Enforce HTTPS: refuse plaintext `http://` targets (see below). Forced on by `--security` |
| `--with-video-session-recording` | Record the session to a video file in this directory |
| `--with-logging` | Audit-log sink: empty/`stderr` for stderr JSONL, or a file path for hash-chained JSONL |
| `--heartbeat-interval` | Heartbeat cadence written to the audit chain (default 30s) |
| `--guardrails-status-addr` / `--guardrails-status-token` | Loopback HTTP status/may-run endpoint + bearer token |
| `--with-kill-switch` | Arm the kill switch (master gate; default off — without it, triggers are detected and audited but contain nothing) |
| `--kill-on-posture-drift` / `--kill-on-circuit-trip` / `--kill-on-rugpull` / `--kill-on-heartbeat-gap` | Kill triggers (all default on; each also requires `--with-kill-switch`) |
| `--kill-action-isolate` | Kill action: firewall isolate the device (default on; requires elevation) |
| `--kill-action-kill-procs` / `--kill-action-proc-names` | Kill action: terminate named processes (requires elevation) |
| `--kill-action-lock` / `--kill-action-shutdown` / `--kill-action-shutdown-delay` | Kill actions: lock / shut down (requires elevation) |
| `--guardrails-bypass` | Break-glass: skip pre-flight checks (logged) |
| `--enable-tier2` + `--graph-*` / `--remote-policy-token` | Opt into the parked tier-2 remote checks (Graph / may-run PDP) |
| `--log-file` | Write debug logs to a file (stdout is reserved for the transport) |

## Enforce HTTPS

Turn on Enforce HTTPS so computer use only works with HTTPS websites. When it is
on, plaintext `http://` targets are refused, which helps protect against data
exposure over the network:

```sh
./windows-mcp-server.exe stdio --enforce-https
```

Off by default, so existing behaviour is unchanged. `--security` force-enables it,
the same way the master switch force-enables the transparency services.

### What it covers

| Entry point | Behaviour when on |
|---|---|
| `Scrape` | An `http://` URL is refused before any request is made. Exact: the server makes this request itself. |
| `App` `mode=launch` | A URL-shaped name is a navigation — `Start-Process http://example.com` hands it to the default browser — so a plaintext URL is refused. An ordinary name like `notepad` is untouched. |
| `remote-policy` guardrail | A plaintext may-run endpoint **fails** the guardrail rather than skipping it: the request carries device identity and a bearer token, so plaintext would disclose both. |

Scheme comparison is case-insensitive, so `HTTP://` and `HtTp://` cannot bypass
it. Blocked results tell the agent to retry over `https://` so it can self-correct
rather than repeating the call.

### What it does not cover

**Browser navigation is not intercepted.** If a browser is already open, the agent
can click a link, use the address bar, or follow a redirect to an `http://` site
without any tool call passing through the server. Enforce HTTPS constrains the
URLs the *server* fetches or opens, not where a browser subsequently goes.

Closing that gap needs enforcement below the tool layer — a device proxy that
filters egress by scheme and host, so it applies however the browser got there.
That is not implemented here.

Also unaffected: the loopback guardrail status endpoint (`--guardrails-status-addr`)
is an inbound HTTP listener bound to localhost and protected by a bearer token,
not a website computer use interacts with. Microsoft Graph URLs are `https://`
constants in the code and are not operator-overridable.

## Credentials

Credentials can be supplied to the server **at init** and are installed into the
Windows Credential Manager for the running user, so anything in that user context
— a browser, an LOB app, RDP, a mapped drive, Windows SSO — can consume them the
normal way. The agent can then sign in without ever being told the secret.

```sh
./windows-mcp-server.exe stdio --credentials-file C:\secure\creds.json
```

```json
{
  "credentials": [
    {
      "name": "corp-sso",
      "target": "login.contoso.com",
      "username": "svc-automation@contoso.com",
      "secret": "…",
      "comment": "optional note stored on the credential"
    }
  ]
}
```

`name` is the handle the agent uses; `target` is the Credential Manager target.
`type` is `generic` (default) or `domain_password`. Supplying the flag enables the
`credentials` toolset automatically — the default toolsets are kept, not replaced.

### The agent can use a secret but never read one

This is the property the whole design is built around:

- **No mode returns plaintext.** The tool has exactly three modes — `list`,
  `verify`, `inject` — and there is deliberately no `get`. A unit test pins the
  mode set so a secret-reading mode cannot be added by accident.
- **`inject` types the secret as keystrokes.** The value is read inside the
  desktop engine, converted straight to input, and the buffers are zeroed. Only
  the number of characters typed is returned. The secret never enters a tool
  result, the audit log, the conversation transcript, or the model's context.
- **Audit records identifiers only** — name, target, username, class — via
  `credentials.installed` and `credentials.removed`.

```jsonc
// list: identifiers plus live presence, never secrets
{"mode": "list"}
// inject at the current focus
{"mode": "inject", "name": "corp-sso"}
// click the password field first, then type, then submit
{"mode": "inject", "name": "corp-sso", "label": 7, "press_enter": true}
{"mode": "inject", "name": "corp-sso", "name_target": "Password", "control_type": "Edit"}
```

`domain_password` credentials are installed for Windows to use but **cannot be
injected** — Windows does not return their blob to a caller. `Credentials`
reports them as `injectable: false` rather than failing opaquely.

### Handling

- **Secrets are never accepted as flags.** `argv` is readable by any process on
  the machine, so a secret on the command line is a secret disclosed. The file is
  the only supply path.
- **The file's real ACL is checked** at startup. If `Everyone`, `Users`,
  `Authenticated Users`, or `INTERACTIVE` can read it, startup fails with the
  `icacls` command to fix it. (Go's Unix permission bits are meaningless here —
  Windows synthesizes `0666` for every normal file.)
- **Session-scoped and cleaned up.** Entries are written with
  `CRED_PERSIST_SESSION` and deleted on *every* shutdown path — normal exit and
  kill-switch trip alike — so a session leaves no credential residue. Durable
  persistence is rejected rather than silently overridden.
- **Installed only after admission.** A startup blocked by pre-flight guardrails
  never provisions credentials. A partial install is rolled back.
- `Credentials` counts as a sensitive tool, so the circuit breaker rate-limits it.

> Secrets are held in process memory between reading the file and installing
> them. Buffers are zeroed, and the JSON decoder avoids materializing an
> unwipeable Go string for unescaped values — but Go offers no guarantee that a
> copy was never made. Treat the host as trusted.

## MCP spec compliance

The project tracks its conformance to the Model Context Protocol as the spec
evolves. `spec-check` runs a real in-process MCP session against the server's own
tool manifest and validates the resulting **wire objects** — handshake result,
capabilities, `tools/list` — against the official JSON Schemas vendored under
`schema/`:

```sh
./windows-mcp-server.exe spec-check                       # newest revision, markdown
./windows-mcp-server.exe spec-check --spec-version all --format json
./windows-mcp-server.exe spec-check --fail-under 80       # exit 2 below threshold
```

The report separates two things that are easy to conflate:

- **Conformance** — does everything the server serves validate against the spec?
  Weighted across tool definitions (45), `tools/list` (20), the handshake (15),
  capabilities (10) and revision currency (10). This is the gateable number:
  `--fail-under 100`.
- **Coverage** — how much of the optional feature surface exists at all. Purely
  informational, because MCP does not require a server to implement prompts,
  resources or completions; a tools-only server is fully conformant. Gate it
  separately with `--fail-coverage-under` if you want to.

A dimension the revision does not define is *skipped* and drops out of the
denominator rather than scoring zero — revisions restructure, and `2026-07-28`
removes `initialize` entirely in favour of `server/discover`. The handshake is
also skipped when scoring a revision other than the one the session negotiated,
since its shape is decided by that negotiation.

Current state: **conformance 100/100 against every vendored revision, zero
findings**, and 100% method coverage on `2026-07-28`.

`.github/workflows/mcp-spec-compliance.yml` runs weekly: it syncs new revisions
from upstream, rescores, raises a PR for the vendored schema, and opens a tracking
issue on a new revision or a score regression. The current report is committed at
[docs/mcp-compliance.md](docs/mcp-compliance.md).

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

**Kill switch — tiered, out-of-band.** Triggers are configured separately from
actions, and **arming is a two-step gate**: `--with-kill-switch` is the master
switch (default **off**), and each trigger additionally honours its own
`--kill-on-posture-drift`/`-circuit-trip`/`-rugpull`/`-heartbeat-gap` flag
(all default on, so arming the master enables them all). A sentinel file and
`POST /revoke` are gated on the master switch alone.

Detection is never gated. When a trigger fires while disarmed it is still
detected, logged, and written to the audit chain as `killswitch.disarmed`
(recording the trigger and reason) — you always see that something fired, even
when you chose not to act on it — and the server keeps serving and keeps
monitoring.

Once armed, a trip **always** raises the banner, seals the audit log, finalizes
the recording, and aborts the session. Opt-in escalations run in order:
`--kill-action-isolate` (firewall block-all; loopback stays exempt so the status
endpoint survives — default on), `--kill-action-kill-procs`
(`--kill-action-proc-names`), `--kill-action-lock`, `--kill-action-shutdown`.
The **default once armed is isolate + abort, no shutdown.**

The agent-facing `Kill` tool is deliberately not an authoritative trigger. It
always stops the session cleanly (audit, seal, finalize the recording, abort),
but it only actuates the containment ladder when the master switch is armed — an
agent can never escalate "stop this session" into network isolation or a
shutdown on an operator who did not arm it.

**Privilege model — best-effort degrade.** The server runs in the (non-admin)
user context. The elevation-only actions (isolate / kill-procs / shutdown) run
only when the process is actually elevated; otherwise they are skipped and
audited (`killaction.skip … not elevated`) while the banner, log-seal,
recording-finalize, and abort still happen.

### Threats this addresses

- **Dynamic rug pulls** — tool-manifest fingerprint + `tools/list` interception +
  periodic recheck (silent `tools/list_changed` is suppressed).
- **Indirect prompt injection / data-exfil loops** — the circuit breaker blocks the
  call and, when the kill switch is armed, escalates to network isolation, cutting
  the exfil channel, then aborts.
- **Out-of-band control** — the status endpoint, audit log, heartbeat, monitor,
  and kill switch are not exposed as tools; the only agent-facing tools are the
  read-only `GuardrailStatus` and `Kill`, which stops the session but cannot
  actuate containment unless the operator armed the switch.

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
internal/mcpspec          MCP schema conformance scorer (platform-agnostic)
pkg/windows              the MCP tool definitions + dependency-injection glue
pkg/inventory            domain-agnostic toolset engine (grouping, filtering,
                         personas, read-only, feature flags)
schema/                  vendored MCP protocol schemas, one dir per revision,
                         plus versions.json and the committed compliance.json
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
