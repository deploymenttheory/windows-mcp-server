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
| `internal/mcpspec` | vendored-schema loader + offline wire validation (platform-agnostic; no build tag) |
| `internal/mcpconf` | official conformance-suite results: ingest + reporting (no build tag) |
| `schema/` | vendored MCP protocol schemas + `versions.json` |
| `conformance/` | expected-failure baselines + committed suite results |

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

## Enforce HTTPS

`--enforce-https` (forced on by `--security`) refuses plaintext `http://` targets.
`pkg/windows/urlpolicy.go` owns the tool-layer policy; `internal/guardrails/remote.go`
applies it to the may-run endpoint via `Env.EnforceHTTPS`.

Two traps to preserve:

- **Compare schemes case-insensitively.** `url.Parse` keeps the caller's case and
  `HTTP://host` is a valid equivalent URL, so a `==` comparison is a trivial
  bypass. Use `strings.EqualFold` / `strings.ToLower`.
- **A URL-shaped value is a navigation.** `App`'s `name` is normally something like
  `notepad`, but `Start-Process http://example.com` opens the default browser.
  `urlSchemeIfURL` exists to spot that, and requires an explicit `://` so a bare
  `example.com` or a file path is not mistaken for a URL.

When adding another URL entry point, gate it through `enforceHTTPSScheme` and add
it to the coverage table in the README's Enforce HTTPS section.

### Testing tool handlers: a nil engine is not a safety net

`fakeDeps` in `pkg/windows/urlpolicy_test.go` returns a nil `*desktop.Desktop`.
That is **only** safe for paths that return before touching the engine. Several
engine methods never dereference their receiver — `LaunchApp` shells out through
`RunPowerShell`, which just builds an `exec.Cmd` — so a handler reaching the
engine with a nil `*Desktop` really performs the action instead of panicking. An
earlier version of these tests opened a browser tab this way.

Assert the blocked path through the handler; assert the allowed path against the
gate helpers directly.

## MCP conformance

The server targets protocol revision **2026-07-28**, and the verdict on whether it
conforms comes from the official suite,
`github.com/modelcontextprotocol/conformance`, run by
`.github/workflows/mcp-spec-compliance.yml`. This replaced a scorer written in
this repo that graded our own wire objects and published 100/100 — a number marked
by the project it graded. Do not reintroduce a score.

- **The suite is HTTP-only.** `--url` is a required option of its `server` command;
  there is no stdio path. Hence `conformance-serve`, in
  `internal/winmcp/conformance_host.go` behind `//go:build ... && conformance`.
  `go build ./...` must never compile it — a released binary with an
  unauthenticated HTTP listener serving the full desktop-automation manifest is
  exactly what the stdio-only posture exists to prevent. The workflow asserts this
  by grepping an untagged build's `--help`.
- **One constructor, or the evidence is worthless.** `newMCPSurface`
  (`internal/winmcp/surface.go`) builds the server for `RunStdio`, `CaptureSurface`
  and the conformance host alike, and installs inject-deps plus cache hints.
  Evidence gathered over HTTP only describes the shipped binary because the two
  serve the same thing; `TestConformanceHostServesTheShippedSurface` is what keeps
  that true. If you add construction anywhere, add it there.
- **Two passes, recorded separately.** The suite's scenarios name fixed fixtures
  (`test_simple_text`, `test://static-text`, …), so a product server cannot pass
  them. `--fixtures` registers exactly those names (also `conformance`-tagged); the
  pass without it is what the product ships. Never merge the two results — the
  distinction is what makes each claim honest.
- **Gate on the suite, never re-derive it.** `--expected-failures` plus its exit
  code already handle both directions: an unlisted failure fails, and a listed
  entry that starts passing also fails. `internal/mcpconf` only ingests and
  renders. Every baseline entry carries its reason.
- **`--suite all`, not `active`.** The harness classifies 2026-07-28 as its draft
  revision, so `active` excludes precisely the scenarios this revision introduced.
- **Pin the harness version exactly.** 2026-07-28 support is on the `0.2.0-alpha`
  line; stable `0.1.x` predates the revision. The workflow reports a newer version
  rather than floating onto it.

`internal/mcpspec` is now just the schema loader plus the revision manifest. It
backs one offline pass/fail check (`capture_test.go`) so `go test` still catches a
broken tool schema without Node, and the workflow's new-revision detector. Keep
lookups def-driven via `Spec.FirstPresent(...)`: revisions restructure (draft-07
`definitions` before 2025-11-25, 2020-12 `$defs` after; 2026-07-28 drops
`InitializeResult` for `DiscoverResult`).

**Capture the wire, not the SDK's view.** `ClientSession.InitializeResult()` is a
*synthesized legacy view* on the new protocol. `recordtransport.go` records real
`jsonrpc.Message` frames; use `frameLog.ResultFor(method)`.

### What 2026-07-28 changed that this code owns

The SDK implements the wire; the gaps were in our layers, and they are load-bearing:

- `server/discover` is the canonical advertisement of capabilities and
  instructions, so `RugPull.DiscoverMiddleware` fingerprints it
  (`HashDiscover` = capabilities + instructions; **not** `supportedVersions`, which
  is transport-derived and differs legitimately between stdio and HTTP).
- `server.discover` and `subscriptions.listen` are audited. Without the first the
  chain holds no record that a client connected — there is no handshake any more.
- `subscriptions/listen` counts against the circuit-breaker window;
  `server/discover` deliberately does not, since a stateless client may probe it
  before every request.
- A blocked non-tool method returns a **JSON-RPC error** (`blockedError`), not an
  `IsError` result. The `IsError` convention is tools-only: answering a
  `resources/read` with a `CallToolResult` puts the wrong envelope on the wire.
- `cacheHintsMiddleware` sets `ttlMs`/`cacheScope` on all six cacheable results.
  The SDK's `"public"` default is wrong here — a `resources/read` returns one
  user's desktop, and the manifest depends on this session's persona and toolsets.

After changing the tool manifest, the workflow regenerates the report; there is no
local command that mints evidence, because evidence has to come from the suite.

## Resources and prompts

Added alongside tools; four rules keep them safe and visible.

- **Fixed resources and resource *templates* are disjoint in the SDK.**
  `resources/list` paginates only fixed resources, `resources/templates/list` only
  templates. Registering templates alone yields an **empty** `resources/list`.
  `inventory.ServerResource` + `RegisterResources` exist for the fixed case; use
  `SetFixedResources` in `NewInventory()`.
- **Attach them to toolsets that already contain tools.** `AvailableToolsets`,
  `EnabledToolsets` and `generateInstructions` iterate `r.tools` only, so a toolset
  introduced solely by a resource or prompt is invisible to all three.
  `TestResourcesAndPromptsUseToolBearingToolsets` enforces this.
- **Prompts have no deps argument.** `inventory.ServerPrompt.Handler` is a bare
  `mcp.PromptHandler`, so a prompt needing the engine must read it from the
  context — which works because `InjectDepsMiddleware` covers every method.
- **Prompt text reuses `Personas[...].Instructions`** via `personaGuidance`, so
  `--persona` and the prompts share one source of truth.

### Capabilities must stay pinned

`Server.capabilities()` *infers* any capability left nil, filling
Prompts/Resources with `ListChanged: true` the moment one is registered. That
re-opens the silent re-advertisement channel rug-pull detection exists to close.
`pinnedCapabilities()` declares all four explicitly with `ListChanged` false —
keep it that way, in `server.go` **and** `speccheck.go`.

### Guardrails cover the new methods

`resources/read` and `prompts/get` are data-egress paths, so they are audited
(`resource.read`, `prompt.get`, arguments digested never raw), `resources/read`
counts against the circuit breaker's window *shared with tools* (so alternating
between a tool and an equivalent resource cannot evade the limit), and both
manifests are rug-pull fingerprinted via `HashPrompts`/`HashResources`. A surface
with no pinned baseline is skipped rather than treated as drift.

## Build tags

Everything is `//go:build windows && (amd64 || arm64)` **except** the
deliberately platform-agnostic files: `pkg/windows/{toolsets,params,result}.go`,
all of `pkg/inventory`, all of `internal/mcpspec`, all of `internal/mcpconf`, and
the `internal/guardrails` core. Preserve that split — it is what keeps the filter
engine, the schema validation, the conformance reporting and the security logic
testable in isolation.

There is one extra tag: **`conformance`**. It adds the loopback HTTP host and the
conformance-suite fixtures and nothing else, and `go build ./...` must never
compile it. Build and test that side explicitly:

```powershell
go build -tags conformance ./...
go test -tags conformance ./internal/winmcp/ -count=1
```

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
