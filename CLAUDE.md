# CLAUDE.md

Guidance for AI coding agents working in this repository. These are the
conventions that are load-bearing but not obvious from any single file — read
this before adding a tool, touching the desktop engine, or changing the security
subsystem.

## What this is

An MCP server (stdio transport only) bridging AI agents to the Windows desktop.
A Go port of the Python [Windows-MCP](https://github.com/CursorTouch/Windows-MCP),
built on `deploymenttheory/go-bindings-win32`, `go-bindings-wmi`, and the official
`modelcontextprotocol/go-sdk`. Perception is the UI Automation accessibility tree
— there is no CV model.

| Package | Role |
|---|---|
| `cmd/windows-mcp-server` | cobra CLI (`stdio`/`check`/`personas`), viper `WINDOWS_MCP_*` env binding |
| `internal/winmcp` | `RunStdio` startup orchestration + the OS adapters (`systemProbe`, health probe, TPM attestation) |
| `internal/desktop` | the Win32/UIA/WMI engine — one COM STA thread |
| `pkg/windows` | tool definitions (one file per topic) + toolset/persona metadata |
| `pkg/inventory` | domain-agnostic toolset filter/registration engine (mirrors `github-mcp-server`) |
| `internal/guardrails` | the four-layer security core |
| `internal/mcpspec` | MCP schema conformance scorer (platform-agnostic; no build tag) |
| `schema/` | vendored MCP protocol schemas + `versions.json` + committed `compliance.json` |

## Build, test, lint

```powershell
go build ./...
go vet ./...
go test ./... -count=1
$env:GOARCH='arm64'; go build ./...   # the (amd64 || arm64) tag is asserted everywhere
golangci-lint run --config=./.golangci.yml
```

CI is **Windows-only by design** (`.github/workflows/go-build-test.yml`): nearly
every file is `//go:build windows`, so a Linux runner would compile almost
nothing. `internal/desktop` tests self-skip when the environment cannot host UIA,
so on a hosted runner CI guarantees compilation plus the pure-logic suites.

Two lint settings shape how you work:

- `.golangci.yml` sets `new: true` with `new-from-merge-base: main` **and**
  `whole-files: true` — touching a file surfaces *all* of its issues, not just
  your diff hunks. Budget for that before editing a long-untouched file.
- Formatters are `gofumpt` + `goimports` + `gci` + `golines` (~120 cols). The
  `gci` section order is **Standard → Default → `Prefix(github.com/deploymenttheory)`**.

Go files are pinned to LF via `.gitattributes`; Go tooling treats CRLF as
misformatted. PR titles must be conventional commits (`pr-title-validation.yml`).

## The STA-thread rule — the engine's central constraint

`internal/desktop` owns **one** COM apartment-threaded OS thread
(`com.go:181-234`). It locks the thread and deliberately never unlocks it, sets
per-monitor-v2 DPI awareness, calls `CoInitializeEx(APARTMENTTHREADED)`, then
`CoInitializeSecurity(... RPC_C_IMP_LEVEL_IMPERSONATE ...)` — that last call is
required or out-of-proc COM (WMI `ExecQuery`) fails `WBEM_E_ACCESS_DENIED`.

Rules that follow:

- **All** COM/UIA/synthetic-input/clipboard/window work goes through
  `Desktop.Do` (`com.go:239`) and is fully serialized. `safeCall` recovers panics
  so one bad call cannot kill the thread.
- `Do` is **never** called from outside `internal/desktop`. Tool handlers call
  engine methods; the engine decides what runs on the STA thread.
- Functions that must run on that thread say so in their doc comment. Keep that
  habit.
- UIA element lifetime is thread-bound: retained elements are `AddRef`'d during
  traversal (`tree.go:92`) and released on the **same** thread when the snapshot
  is swapped (`snapshot.go:77-83`). Never release from a caller goroutine.
- **WMI is MTA**, not STA — `go-bindings-wmi` initializes `COINIT_MULTITHREADED`
  and is thread-affine, so it gets its own worker (`wmi.go:35-52`), and
  `QueryWMI` spawns a fresh goroutine per call for non-`cimv2` namespaces.
- The overlay has its own locked thread and message pump, reached only by a
  non-blocking channel send that **drops on overflow** — decoration must never
  stall automation.
- `captureScreen` (`capture.go:16-19`) creates its own DCs and is deliberately
  thread-agnostic; that is what lets the recorder goroutine capture frames
  concurrently. Don't "fix" it by routing it through `Do`.
- The `EnumWindows`/`EnumDisplayMonitors` callbacks are package-level
  `syscall.NewCallback` values with package-level sinks and no mutex. That is
  correct *only* because all enumeration happens on the one serialized thread.

## Hand-declared CLSIDs

The generated bindings emit some COM classes as empty marker structs with no
GUID, so the CLSID is declared locally: `clsidCUIAutomation` (`uia.go:18-23`) and
`clsidNetFwPolicy2` (`firewall_windows.go:15-23`). IIDs *are* generated
(`accessibility.IID_IUIAutomation`). If you add a COM class and the binding has
no CLSID constant, follow this pattern and comment why.

## Adding a tool

All 27 inventory tools use `NewToolFromHandler` (`pkg/windows/dependencies.go:136`).
The generic `NewTool[In, Out]` exists but has zero users — prefer the established
path. Canonical shape (see `pkg/windows/clipboard.go:15-69`):

```go
func Clipboard() inventory.ServerTool {
    return NewToolFromHandler(
        ToolsetSystem,                                  // 1. toolset membership
        mcp.Tool{
            Name: "Clipboard", Description: "...",
            Annotations: &mcp.ToolAnnotations{Title: "Clipboard get/set", ReadOnlyHint: false},
            InputSchema: &jsonschema.Schema{Type: "object", /* ... */},
        },
        func(ctx context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
            args, err := ArgsMap(req)                   // 2. always ArgsMap first
            if err != nil { return NewToolResultError(err.Error()), nil }
            text, err := deps.Desktop().ClipboardGet()   // 3. OS work via deps.Desktop()
            if err != nil { return NewToolResultErrorFromErr("failed to read clipboard", err), nil }
            return NewToolResultText(text), nil          // 4. result constructor, nil Go error
        },
    )
}
```

Checklist:

1. Topic file under `pkg/windows`, `func X() inventory.ServerTool`.
2. `Annotations.Title` plus a correct `ReadOnlyHint`; add `DestructiveHint` /
   `OpenWorldHint` pointers where apt (see `shell.go:18-30`).
3. `InputSchema: &jsonschema.Schema{Type: "object", ...}`.
4. Parse with `ArgsMap` then the `params.go` accessors — **never hand-roll arg
   parsing**. They coerce on purpose: Claude Desktop strips `anyOf` and
   stringifies bools/arrays (`params.go:12-15`), so `OptionalIntSlice` accepts
   both `[10,20]` and `"[10,20]"`, and `OptionalBool` accepts `true/1/yes`.
5. Register in the correct comment group of `AllTools()` (`tools.go:15-60`).
6. **Bump `TestExpectedToolCount`** (`tools_test.go:53`) — it is a deliberate
   tripwire, not an annoyance.
7. Extend `TestReadOnlyToolsAreSafe` / `TestDestructiveToolsAreWrite` if it
   belongs in either list.
8. If the tool is state-changing, consider adding its name to `sensitiveTools`
   (`internal/guardrails/policy.go:37`) so the circuit breaker counts it.

### The `IsError` convention — read this before returning an error

Documented at `pkg/windows/result.go:22-25` and enforced by convention
everywhere: an **expected or user-facing failure returns an `IsError` result with
a nil Go error**, so the model can read the message and self-correct. A non-nil
Go error is reserved for genuine infrastructure failure. Use only the `result.go`
constructors (`NewToolResultText`, `NewToolResultErrorFromErr`, …).

### Dependency injection is middleware, not closures

`InjectDepsMiddleware` (`dependencies.go:88`) puts `ToolDependencies` on the
context; handlers pull it via `MustDepsFromContext`. The `deps` argument passed
to `RegisterTools` is ignored by every handler — the context is the real path.
Receiving-middleware order, outermost first (`internal/winmcp/server.go:239-252`):
**inject-deps → audit → rug-pull → tool-policy**. Order matters; audit must see
the call, and policy must be innermost so nothing bypasses it.

### Personas and toolsets

A persona (`toolsets.go:74-142`) is *only* a (toolset selection + read-only
stance + instructions text) preset over the one manifest. Adding a persona never
means adding tools. `pkg/inventory` also supports resources and prompts and an
`InstructionsFunc` per toolset — currently unused; don't assume they're wired.

## The security subsystem

Four layers plus an out-of-band kill switch; see `docs/security-architecture.md`
for the full design and diagrams. Two invariants that are easy to break:

- **Transparency is never conditional on containment.** A kill trigger that fires
  while disarmed must still be detected, logged, and appended to the audit chain
  (`killswitch.disarmed`). `tripFunc` (`internal/winmcp/guardrails.go`) is the
  single gate: `--with-kill-switch` is the master, each trigger also honours its
  own `--kill-on-*` flag.
- **A report-only trip must not end the in-flight monitor.** `MonitorConfig.Stopped`
  gates loop exit and only a real trip sets it. Returning unconditionally after a
  trip would make disarming one trigger silently disable all monitoring.

Also: the kill ladder's ordering in `killaction.go:92-159` is deliberate — audit,
banner, and **seal** happen before any containment, and the recording is finalized
before shutdown, or the forensic trail is lost. Don't reorder it. The agent-facing
`Kill` tool is intentionally *not* an authoritative trigger; it routes to
`StopGracefully` unless the operator armed the switch.

The guardrails core stays platform-agnostic behind `SystemProbe` / `HealthProbe` /
`SystemActuator` with `actuator_stub.go` for `!windows`, so it is unit-testable
without a Windows host. Keep new logic behind those interfaces rather than
reaching for Windows APIs directly in the core.

## Credentials — the never-read invariant

`internal/desktop/credentials.go` is the **only** place in the server that touches
a plaintext credential after it leaves the config file. The invariant: the agent
can *use* a secret but can never *read* one.

- No function in `internal/desktop` returns a secret. `readSecretUnits` returns
  UTF-16 code units, not a string, precisely so a refactor cannot hand one to a
  caller; `InjectCredential` converts them straight to keystrokes and zeroes the
  buffer. Only the character count comes back.
- The `Credentials` tool has exactly three modes — `list`, `verify`, `inject` —
  and `TestCredentialsToolNeverReturnsSecrets` pins that set. **Do not add a
  `get`/`read` mode**: it would put plaintext into the model's context.
- `ToolDependencies.Credentials()` returns `[]desktop.CredentialInfo`, which has
  no secret field. `TestCredentialInfosOmitSecretsAndDefault` asserts on the
  serialized *keys* (not substrings — `domain_password` is a class name, not a
  secret).
- Audit gets identifiers only (`credentials.installed` / `credentials.removed`).
- Secrets are never accepted as flags: argv is world-readable.
- `checkCredentialsFileACL` reads the **real DACL**. Never substitute a
  `Mode().Perm()` check — Windows synthesizes `0666` for every normal file, so a
  Unix-bits check both proves nothing and can never be satisfied.
- Installation happens only after guardrail admission, and removal runs on every
  shutdown path via a `sync.Once`-guarded closure shared by the normal-exit defer
  and the kill executor's `Finalize`.
- `domain_password` blobs are write-only by design; `CredentialType.Readable()`
  gates injection so the failure is explained rather than opaque.

Note `leftClickAt` (`input.go`): STA-only, for use *inside* a `Do` job. Don't call
`Click` from within a `Do` job — it wraps itself in `Do` and would deadlock on the
unbuffered job channel.

## MCP spec compliance

`internal/mcpspec` scores the served surface against the vendored schemas. Two
things to preserve:

- **Score the wire bytes, not the Go types.** `winmcp.CaptureSurface` runs a real
  in-process MCP session over `mcp.NewInMemoryTransports()` and feeds the actual
  `tools/list` / handshake JSON to the scorer. Re-marshalling our structs would
  hide exactly the divergence this is for. It mirrors `RunStdio`'s server
  construction deliberately — keep them in step.
- **Checks are def-driven, never hardcoded.** Revisions restructure: draft-07 with
  `definitions` before 2025-11-25 and 2020-12 with `$defs` after; `ToolAnnotations`
  does not exist in 2024-11-05; `2026-07-28` removes `InitializeResult` entirely in
  favour of `DiscoverResult`. Use `Spec.FirstPresent(...)` and let a missing
  definition *skip* the dimension — skipped weight leaves the denominator, so a
  removed feature cannot depress the score.

Server method coverage is derived from the schema's `ClientRequest` union (the
requests a client sends), which is why client-side methods like
`sampling/createMessage` correctly never count against us.

After changing the tool manifest, regenerate the committed report:

```powershell
go run ./cmd/windows-mcp-server spec-check --spec-version all --format json --out schema/compliance.json
go run ./cmd/windows-mcp-server spec-check --spec-version all --format markdown --out docs/mcp-compliance.md
```

## Build tags

Everything is `//go:build windows && (amd64 || arm64)` **except** the
deliberately platform-agnostic files: `pkg/windows/{toolsets,params,result}.go`,
all of `pkg/inventory`, all of `internal/mcpspec`, and the `internal/guardrails`
core. Preserve that split — it is what keeps the filter engine, the conformance
scorer, and the security logic testable in isolation.

## Notable gotchas

- **stdout is reserved** for the MCP stdio transport. Logs go to stderr or a file
  (`newLogger`, `server.go:451`); the audit `stderrSink` writes `AUDIT {json}`
  lines to stderr for the same reason.
- **`winenv.go` exists because MCP hosts strip the environment.** It rebuilds
  `PATH` and friends from the registry (merging, not overwriting, PATH). Resolve
  executables with `resolvePwsh` / `lookPathIn` and pass `powerShellEnv()` to any
  `exec.Cmd` — don't rely on the inherited environment.
- **PowerShell is invoked via `-EncodedCommand`** (base64 UTF-16LE,
  `powershell.go:29`), which removes all shell-quoting concerns. Toasts
  specifically need Windows PowerShell 5.1 (`RunWindowsPowerShell`) because
  pwsh 7 does not expose the WinRT APIs.
- `Capabilities.Tools = &mcp.ToolCapabilities{}` (`server.go:210`) deliberately
  suppresses `tools/list_changed` — a silent manifest change is exactly what the
  rug-pull detector exists to catch.
