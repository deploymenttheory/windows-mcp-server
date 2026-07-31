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

## Safety

> **Several tools (PowerShell, Registry, FileSystem, Process, App) have full
> system access with no sandboxing.** Run in a VM or Windows Sandbox for
> untrusted workloads — see [docs/vm-isolation.md](docs/vm-isolation.md) for the
> isolation options, including disposable, Hyper-V-Manager-invisible **HCS**
> sandboxes.

This is the design, not an oversight; see
[SECURITY.md](SECURITY.md) for what is and is not in scope as a vulnerability,
and [Security — the policy engine](#security--the-policy-engine) for the in-process
controls.

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

Subcommands: `stdio` (run the server), `policy` (validate a policy document, check
this device, explain which rules cover a tool), `personas` (list the presets), and
`conformance-report` (render results from the official MCP conformance suite).

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

Resources and prompts are decided by the policy engine like tools are:
`resources/read` and `prompts/get` are written to the hash-chained audit log, both
are covered by any rule matching `toolset: "*"` or `annotation: read-only`, and
both manifests are fingerprinted for rug-pull detection.

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
| `--policy-config` | Path to the device-policy JSON document. Omit for the built-in default, which evaluates every declared signal and records every verdict but refuses nothing. See [docs/policy-config.md](docs/policy-config.md) |
| `--toolsets` | Comma-separated toolsets to enable (`all`, `default`, or specific IDs) |
| `--tools` | Additionally enable individual tools (bypasses toolset filtering) |
| `--exclude-tools` | Disable specific tools |
| `--read-only` | Expose only read-only tools |
| `--persona` | Select a persona preset |
| `--overlay` | Visual feedback overlays (see below) |
| `--record-fps` | Recording frame rate (default 4) |
| `--record-codec` | `h264`/`h265` (via ffmpeg; small files) or `mjpeg` (pure-Go, no dependency) |
| `--credentials-file` | JSON file of credentials to install into the Windows Credential Manager at init (see Credentials) |
| `--log-file` | Write debug logs to a file (stdout is reserved for the transport) |

Everything the security subsystem does — which device signals are read and how
often, which rules cover which tools, what a failure does, what trips the kill
switch and what it actuates, where the audit chain is written, whether the
session is recorded — is configured in the policy document rather than by flags.
The questions are relational, and a flag cannot express a relation: "PowerShell
requires MDM enrolment but taking a screenshot does not" has no spelling as a set
of booleans.

[docs/policy-config.md](docs/policy-config.md) is the schema reference, and
carries a table mapping each removed flag to its field.

## Enforce HTTPS

Turn on Enforce HTTPS so computer use only works with HTTPS websites. When it is
on, plaintext `http://` targets are refused, which helps protect against data
exposure over the network:

```sh
./windows-mcp-server.exe stdio --enforce-https
```

Off by default. Turn it on with `"enforce_https": true` in the policy document.

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

Also unaffected: the loopback status endpoint (`transparency.status_addr`)
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
- `Credentials` is a destructive tool, so any rate limit matching that annotation
  covers it.

> Secrets are held in process memory between reading the file and installing
> them. Buffers are zeroed, and the JSON decoder avoids materializing an
> unwipeable Go string for unescaped values — but Go offers no guarantee that a
> copy was never made. Treat the host as trusted.

## MCP conformance

The server targets protocol revision **`2026-07-28`**. Conformance is measured by the
official suite,
[modelcontextprotocol/conformance](https://github.com/modelcontextprotocol/conformance),
which `.github/workflows/mcp-spec-compliance.yml` runs against the server and commits
the results of.

`2026-07-28` is a stateless protocol: there are no protocol sessions and no
`initialize` handshake. Each request carries its protocol version and client
capabilities in `_meta`, `server/discover` advertises identity and capabilities,
`subscriptions/listen` carries server-to-client notifications, every result carries
`resultType`, every list and read result carries `ttlMs` and `cacheScope`, POSTs carry
`Mcp-Method` / `Mcp-Name` headers, and MCP error codes sit in the `-32020..-32099`
range the spec reserves.

### Running the suite

The suite's `server` mode reaches a server over HTTP: `--url` is required and there is
no stdio path. The conformance host provides one, behind the `conformance` build tag:

```powershell
go build -tags conformance -o conformance-host.exe ./cmd/windows-mcp-server
./conformance-host.exe conformance-serve --addr 127.0.0.1:3001            # product pass
./conformance-host.exe conformance-serve --addr 127.0.0.1:3002 --fixtures # fixtures pass

npx -y @modelcontextprotocol/conformance@0.2.0-alpha.10 server `
  --url http://127.0.0.1:3001/mcp --suite all --spec-version 2026-07-28 `
  --expected-failures conformance/baseline-product.yml
```

`--suite all` is required: the suite classifies `2026-07-28` as its draft revision, so
`--suite active` excludes the scenarios that revision introduced.

`go build ./...` does not compile the host, so **the released binary has no HTTP
listener** and is stdio-only. The host binds loopback addresses only, and refuses
anything else. Both it and `stdio` build their MCP surface through one function
(`newMCPSurface`) and the same middleware chain, so what the suite measures is what the
shipped binary serves; `TestConformanceHostServesTheShippedSurface` fails if their
manifests or capabilities diverge.

### The two passes

- **product** — the manifest the server ships. The suite's `tools/call`,
  `resources/read` and `prompts/get` scenarios invoke fixed fixture names
  (`test_simple_text`, `test://static-text`, …) that this server does not expose, so
  they sit in `conformance/baseline-product.yml` with a reason each. This pass covers
  the transport and wire conformance above, plus the suite's schema validation of every
  message the server sends.
- **fixtures** — the same server with `--fixtures`, which registers those names so the
  handler paths behind them are exercised. The fixtures exist only under the
  `conformance` build tag.

A third run at `2025-11-25` records backward compatibility.

CI gates on the suite's own exit code: a failure absent from the baseline fails the
build, and so does a baseline entry that has started passing.

### The badge

The conformance badge is written by the workflow run that produces the results and
committed to `conformance/badge.json`; shields.io renders that file, so the figure
moves only when a run reaches `main`.

It reports the **product** pass — the share of checks that ran and passed. Skipped
checks are excluded from both sides, since a scenario the revision does not apply to
counts neither for nor against the server. Checks that are expected to fail are
included, so scenarios listed in `conformance/baseline-product.yml` hold the figure
below 100%. The second badge is the workflow's status: green means every pass matched
its baseline.

The badge is a summary; [the report](docs/mcp-compliance.md) is the verdict, with raw
`checks.json` under `conformance/results/`. `conformance-report` renders them:

```sh
./windows-mcp-server.exe conformance-report \
  --pass product=conformance/results/product-checks.json \
  --pass fixtures=conformance/results/fixtures-checks.json
```

Without Node installed, `go test ./internal/winmcp/` still validates every served tool,
the `tools/list` result, the capabilities and the handshake against the schemas
vendored under `schema/`, offline and pass/fail.

## Visual feedback overlays

For screen capture and video recording, `--overlay` draws click-through,
top-most overlays so a viewer can see what the automation is doing:

- a **green hue** around the focused window on each `Snapshot`, and
- an **orange flash** at each click point.

Overlays never intercept input or take focus.

## Session recording

For audit and playback, `transparency.recording_dir` in the policy document records
the **entire session** to a
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
  --policy-config policy.json --record-codec h265 --record-fps 4
```

## Security — the policy engine

> 📐 **Full architecture with diagrams:** [docs/security-architecture.md](docs/security-architecture.md)
> 📄 **Schema reference and flag migration:** [docs/policy-config.md](docs/policy-config.md)

A policy engine sits between the MCP caller and the tools. Before a tool runs, a
resource is read or a prompt is fetched, it evaluates device signals — MDM
enrolment, Entra join, Secure Boot, BitLocker, VBS/HVCI, TPM attestation — against
rules in a policy document, and decides what happens.

```
MCP client ──▶ audit ──▶ rug-pull ──▶ policy engine ──▶ tool handler
                                            │
                                      device signals
```

```sh
windows-mcp-server.exe stdio --policy-config C:\ProgramData\windows-mcp\policy.json
```

With no `--policy-config` the built-in default applies: the engine is present,
every declared signal is evaluated and every verdict recorded, and nothing is
refused. Adopting the engine cannot break a working deployment before its policy
is written.

### Verdicts

| `on_fail` | | Effect |
|---|---|---|
| `allow` | green | Proceeds; the failure is still recorded |
| `warn` | amber | Proceeds, and the warning is attached to the result so the model sees it |
| `deny` | red | This call is refused, and re-evaluated next time — a signal that recovers restores service with no restart |
| `kill` | out of bounds | The kill switch trips and the containment ladder runs |

The verdict is the highest severity among the failures. `"mode": "audit"` caps it
at `warn` while still evaluating everything and recording what enforcing *would*
have done.

### Rules scale with what a call can do

Rules match on tool, toolset, or MCP annotation, so a screenshot is not gated on
the posture a shell command is gated on:

```jsonc
{
  "version": 1,
  "mode": "enforce",
  "signals": {
    "run-context": { "ttl": "0s" },        // live on every call
    "bitlocker":   { "ttl": "60s" },       // cached, refreshed in the background
    "mdm-enrolled":{ "ttl": "5m" }
  },
  "rules": [
    { "name": "baseline",    "match": { "toolset": "*" },              "require": ["run-context"],  "on_fail": "deny" },
    { "name": "destructive", "match": { "annotation": "destructive" }, "require": ["bitlocker"],    "on_fail": "deny" },
    { "name": "shell",       "match": { "tool": "PowerShell" },        "require": ["mdm-enrolled"], "on_fail": "kill" }
  ]
}
```

Requirements are the union across matching rules, so adding a rule never drops a
requirement. Severity is attributed per signal to the most specific rule
requiring it: tool > annotation > named toolset > `"*"`.

`policy explain --tool PowerShell` prints exactly which rules cover a tool and
what they require, evaluating nothing — so a refusal in the field is
attributable without re-running device probes.

### Signal freshness

Device probes are expensive: `dsregcmd`, WMI and `tpmtool` cost hundreds of
milliseconds each, and a desktop session makes many small tool calls. Each signal
carries a `ttl`; readings are cached and refreshed in the background by the
in-flight monitor. `"ttl": "0s"` opts a signal into live evaluation on every
request. The cache starts *unread* rather than passing, so the first calls of a
session are never admitted without having looked at the device.

### Always-on transparency

The agent cannot switch any of this off, and none of it is conditional on
containment — you always see that something fired, even when you chose not to act
on it.

- **Hash-chained audit log** — every decision, action and security event is an
  append-only, tamper-evident entry committing to the previous entry's hash. Tool
  calls record the tool name and an **argument digest**, never raw arguments.
  Every policy verdict is recorded, including allows.
- **On-screen security banner** — a security event raises a persistent red banner,
  drawn on screen and captured by the session recording.
- **Heartbeat** — periodic chained entries, so an external watcher or the
  in-process watchdog detects a stall.
- **Rug-pull detection** — the tool manifest, the prompt and resource manifests,
  and the `server/discover` advertisement are all fingerprinted at startup. If any
  mutates afterwards, the served response and the periodic monitor both catch it.

### Kill switch — tiered, out-of-band

A trip **always** raises the banner, seals the audit log, finalizes the recording
and aborts the session, before any containment. Containment is opt-in and runs in
a fixed order: isolate (firewall block-all; loopback stays exempt so the status
endpoint survives), kill named processes, lock, shut down.

Two things arm it, both in the policy document: a rule's `on_fail: "kill"`, and
the `kill.triggers` block for the sources that have no rule severity of their own
— posture drift, rug-pull, heartbeat gap, and the sentinel file.

The agent-facing `Kill` tool is deliberately not an authoritative trigger. It
always stops the session cleanly, but actuates the containment ladder only when
the policy configures containment — an agent can never escalate "stop this
session" into network isolation on an operator who did not ask for it.

**Privilege model — best-effort degrade.** The server runs in the non-admin user
context. Elevation-only actions run only when the process is actually elevated;
otherwise they are skipped and audited (`killaction.skip … not elevated`) while
the banner, log seal, recording finalize and abort still happen.

### Working with a policy

```sh
windows-mcp-server.exe policy validate --policy-config policy.json   # document + signal ids
windows-mcp-server.exe policy check    --policy-config policy.json   # this device, right now
windows-mcp-server.exe policy explain  --policy-config policy.json --tool PowerShell
```

`validate` reads no device state, reports every problem at once and exits 1, so it
runs in CI. `check` reads every declared signal live and exits 2 when the device is
not admitted, so health probes can gate on posture.

Four starting points ship in `policy/examples/`: `audit.json` (adopt first —
refuses nothing), `secure.json`, `enterprise.json` and `locked-down.json`.

### Threats this addresses

- **Dynamic rug pulls** — tool-manifest fingerprint + `tools/list` interception +
  periodic recheck (silent `tools/list_changed` is suppressed).
- **Indirect prompt injection / data-exfil loops** — a rate limit refuses the call
  and, at `on_exceed: "kill"`, escalates to network isolation, cutting the exfil
  channel, then aborts.
- **Posture drift mid-session** — every call is decided against signals that are
  refreshed continuously, so a device that loses BitLocker or drops off MDM stops
  being allowed to act within one TTL rather than at the next restart.
- **Out-of-band control** — the status endpoint, audit log, heartbeat, monitor,
  and kill switch are not exposed as tools; the only agent-facing tools are the
  read-only `GuardrailStatus` and `Kill`, which stops the session but cannot
  actuate containment unless the policy configures it.

### Trust model — read this

The local device signals (`dsregcmd`, registry, WMI) are **auditable
defense-in-depth, not a hard boundary** — a local admin can spoof them. The
containment layers raise the cost of, and record, in-session compromise but do not
replace the OS controls you already own — pair them with **WDAC/AppLocker**,
Conditional Access, and **code signing**. The authoritative remote signals
(Microsoft Graph device compliance, external may-run PDP) register only when their
credentials are present in the environment; TPM attestation (`tpm-attested`)
requires elevation.

## Architecture

```
cmd/windows-mcp-server   Cobra/Viper CLI (stdio transport)
internal/guardrails      the policy engine: document schema, signal registry +
                         TTL cache, rule matcher, enforcement middleware,
                         audit chain, rug-pull detection, kill switch, status
policy/examples          starting-point policy documents
internal/winmcp          server bootstrap: inventory + MCP server + deps middleware
internal/desktop         the Windows engine — a dedicated COM STA thread serving
                         UIA traversal, SendInput, GDI screenshots, overlays,
                         PowerShell, and a WMI worker thread
internal/mcpspec         vendored-schema loader + offline wire validation
internal/mcpconf         official conformance-suite results: ingest + reporting
pkg/windows              the MCP tool definitions + dependency-injection glue
pkg/inventory            domain-agnostic toolset engine (grouping, filtering,
                         personas, read-only, feature flags)
schema/                  vendored MCP protocol schemas, one dir per revision,
                         plus versions.json
conformance/             expected-failure baselines and the committed results
                         of the official conformance suite
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
