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
| `screen` | ✓ | `Snapshot`, `Screenshot`, `DisplayInventory` |
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
| `--log-file` | Write debug logs to a file (stdout is reserved for the transport) |

## Visual feedback overlays

For screen capture and video recording, `--overlay` draws click-through,
top-most overlays so a viewer can see what the automation is doing:

- a **green hue** around the focused window on each `Snapshot`, and
- an **orange flash** at each click point.

Overlays never intercept input or take focus.

## Architecture

```
cmd/windows-mcp-server   Cobra/Viper CLI (stdio transport)
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
