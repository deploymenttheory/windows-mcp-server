# Getting started

From nothing to an MCP client driving the Windows desktop, then the two things
worth doing before you point it at anything real.

- [Build](#build)
- [First run](#first-run)
- [Connect a client](#connect-a-client)
- [Choose what the agent can do](#choose-what-the-agent-can-do)
- [Before anything real](#before-anything-real)

---

## Build

Requires Windows 10 or 11 (amd64 or arm64) and Go 1.25+.

```powershell
go build -o windows-mcp-server.exe ./cmd/windows-mcp-server
```

One binary, no runtime dependencies. (ffmpeg is optional and only for
smaller recording files — see [Session recording](recording.md).)

---

## First run

The server speaks MCP over stdio, so running it by hand just waits on stdin.
That is enough to confirm it starts:

```powershell
.\windows-mcp-server.exe stdio
# Ctrl-C to stop
```

Startup logs go to stderr — stdout belongs to the transport. You should see the
device policy load and the toolsets resolve.

Check what it would serve, and what the device looks like:

```powershell
.\windows-mcp-server.exe personas                    # the presets
.\windows-mcp-server.exe policy check                # this device, against the default policy
```

---

## Connect a client

Everything after `--` (or in `args`) is the command the client launches. Use the
absolute path to the binary, and escape backslashes in JSON.

### Claude Code

```powershell
claude mcp add windows --scope user -- "C:\path\to\windows-mcp-server.exe" stdio --persona first-line-support
```

Or commit a project-scoped `.mcp.json`:

```json
{
  "mcpServers": {
    "windows": {
      "command": "C:\\path\\to\\windows-mcp-server.exe",
      "args": ["stdio", "--persona", "first-line-support",
               "--policy-config", "C:\\ProgramData\\windows-mcp\\policy.json"]
    }
  }
}
```

Verify with `claude mcp list`; inside a session, `/mcp` lists the tools.

### Cursor

`.cursor/mcp.json` in the project, or `%USERPROFILE%\.cursor\mcp.json` for all
projects, then enable it under **Settings → MCP**:

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

```powershell
codex mcp add windows -- "C:\path\to\windows-mcp-server.exe" stdio --persona business-user
```

Or `%USERPROFILE%\.codex\config.toml`:

```toml
[mcp_servers.windows]
command = "C:\\path\\to\\windows-mcp-server.exe"
args = ["stdio", "--persona", "business-user"]

[mcp_servers.windows.env]
WINDOWS_MCP_OVERLAY = "true"
```

### Claude Desktop

`claude_desktop_config.json` (Settings → Developer → Edit Config):

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

### Any other stdio client

Command: the absolute path to the exe. First argument: `stdio`. Everything else
is optional configuration. There is no URL to configure — MCP is spoken over
stdio only. (The policy document can stand up two loopback HTTP listeners — the
[status endpoint](monitoring.md) and the [egress proxy](egress.md) — but neither
carries MCP.)

> **Escaping:** JSON needs `C:\\path\\...`; TOML accepts `\\` or a single-quoted
> literal `'C:\path\...'`. If the binary is on `PATH`, the bare name works.

---

## Choose what the agent can do

The default selection is `screen`, `interaction`, `apps`, `system` — enough to
see the desktop and drive it, without a shell or the filesystem.

```powershell
--persona qa-test-engineer            # a preset: toolsets + stance + instructions
--toolsets all --exclude-tools PowerShell,Registry
--read-only                           # only read-only tools
```

See [Toolsets and personas](toolsets-and-personas.md) for what each tool does and
how the knobs combine.

---

## Before anything real

Two things, in this order.

### 1. Understand the blast radius

`PowerShell`, `Registry`, `FileSystem`, `Process` and `App` have **full system
access with no sandboxing**. That is the design, not an oversight. For untrusted
workloads run the whole thing in a VM or Windows Sandbox — see
[VM isolation](vm-isolation.md).

### 2. Write a policy, starting in audit mode

With no `--policy-config`, the built-in default evaluates every declared signal
and records every verdict but **refuses nothing**. That is deliberate: adopting
the engine cannot break a working deployment before its policy is written.

Start from the shipped example that refuses nothing, and watch what it would do:

```powershell
copy policy\examples\audit.json C:\ProgramData\windows-mcp\policy.json
.\windows-mcp-server.exe policy validate --policy-config C:\ProgramData\windows-mcp\policy.json
.\windows-mcp-server.exe stdio --policy-config C:\ProgramData\windows-mcp\policy.json
```

Every verdict is written to the audit log including the `intended` severity, so
you can see exactly what `"mode": "enforce"` would have refused before you switch
it on. When the log is quiet, flip the mode.

```powershell
.\windows-mcp-server.exe policy explain --policy-config policy.json --tool PowerShell
```

`explain` prints which rules cover a tool and what they require, evaluating
nothing — so a refusal in the field is attributable without re-running probes.

---

## Where next

| If you want to | Read |
|---|---|
| Gate tools on device posture | [Policy configuration](policy-config.md) |
| Restrict which domains the device may reach | [Egress setup](egress.md) |
| Let the agent sign in without seeing secrets | [Credentials](credentials.md) |
| Record sessions for audit or playback | [Session recording](recording.md) |
| Watch the server from outside | [Monitoring](monitoring.md) |
| Deploy this on managed machines | [Deployment](deployment.md) |
| Understand the security design | [Security architecture](security-architecture.md) |
