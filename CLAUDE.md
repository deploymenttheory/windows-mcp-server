# CLAUDE.md

Guidance for AI coding agents working in this repository. These are the
conventions that are load-bearing but not obvious from any single file — read
this before adding a tool, touching the desktop engine, or changing the security
subsystem.

## What this is

An MCP server (stdio transport only) bridging AI agents to the Windows desktop.
A Go port of the Python [Windows-MCP](https://github.com/CursorTouch/Windows-MCP),
built on `deploymenttheory/go-bindings-win32`, `go-bindings-wmi`, the shared
`deploymenttheory/mcp-server-core` (the platform-agnostic half: inventory,
toolkit, surface, runtime, conformance host, journeys), the
`deploymenttheory/agentweave-harness` guardrails, and the official
`modelcontextprotocol/go-sdk`. Its sibling, macos-mcp-server, is the same
design on the other platform and consumes the same core. Perception is the UI Automation accessibility tree
— there is no CV model.

| Package | Role |
|---|---|
| `cmd/windows-mcp-server` | cobra CLI (`stdio`/`check`/`personas`), viper `WINDOWS_MCP_*` env binding |
| `internal/winmcp` | `RunStdio` startup orchestration + the OS adapters (`systemProbe`, health probe, TPM attestation, credentials and the DACL check, the go-winio harness dial) |
| `internal/desktop` | the Win32/UIA/WMI engine — one COM STA thread |
| `pkg/windows` | tool definitions (one file per topic) + toolset/persona metadata, and the `dependencies.go` shim over the shared toolkit |
| `internal/psdata` | PowerShell data binding (`PSScript`), the one defence against a value becoming source text |
| `mcp-server-core` (imported) | inventory engine, tool toolkit, MCP surface, guardrail runtime, journeys, run records, schema loader, conformance host + fixtures, conformance-results reporting |
| `agentweave-harness/guardrails/*` (imported) | the security stack, split by lifecycle layer (see below) |
| `policy/examples` | starting-point policy documents (validated by the test suite) |
| `schema/` | vendored MCP protocol schemas + `versions.json` |

## Build, test, lint

```powershell
go build ./...
go vet ./...
go test ./... -count=1
$env:GOARCH='arm64'; go build ./...   # the (amd64 || arm64) tag is asserted everywhere
golangci-lint run --config=./.golangci.yml
```

From a Mac or Linux box the Windows packages cannot run but they cross-compile
and type-check, which is enough to work on the wiring: `GOOS=windows
GOARCH=amd64 go build ./...`, `go vet ./...`, `go build -tags conformance
./...` and `golangci-lint run` with the same `GOOS`. CI runs the real tests.

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

All 35 inventory tools use `NewToolFromHandler` (`pkg/windows/dependencies.go`), a
thin wrapper over `toolkit.NewToolFromHandler[ToolDependencies]`. The generic
`toolkit.NewTool[D, In, Out]` exists but has zero users — prefer the established
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
4. Parse with `ArgsMap` then the `toolkit` accessors (re-exported from
   `dependencies.go`) — **never hand-roll arg parsing**. They coerce on purpose:
   Claude Desktop strips `anyOf` and stringifies bools/arrays, so `OptionalIntSlice` accepts
   both `[10,20]` and `"[10,20]"`, and `OptionalBool` accepts `true/1/yes`.
5. Register in the correct comment group of `AllTools()` (`tools.go:15-60`).
6. **Bump `TestExpectedToolCount`** (`tools_test.go:53`) — it is a deliberate
   tripwire, not an annoyance.
7. Extend `TestReadOnlyToolsAreSafe` / `TestExecutionPrimitivesAreAnnotatedDestructive`
   if it belongs in either list.
8. Set `DestructiveHint` honestly. Policy rules match on it, so it is what decides
   whether a tool is covered by a rule requiring hardware posture, or by a rate
   limit. It is load-bearing metadata now, not documentation.
   `TestEveryWriteToolIsAnnotatedDestructive` makes this deny-by-default: a tool
   that is not read-only must carry the hint or be listed there with a reason.
   Do not add an exemption to quiet the test — it is the register of what a
   `annotation: destructive` rule does not reach. Seven tools were once outside
   every shipped gate because the older allowlist test only checked the names
   someone had thought to add.

### The `IsError` convention — read this before returning an error

Documented on `mcp-server-core/toolkit`'s result constructors and enforced by
convention everywhere: an **expected or user-facing failure returns an `IsError` result with
a nil Go error**, so the model can read the message and self-correct. A non-nil
Go error is reserved for genuine infrastructure failure. Use only the `toolkit`
constructors (`NewToolResultText`, `NewToolResultErrorFromErr`, …), re-exported
from `dependencies.go`.

### Dependency injection is middleware, not closures

`toolkit.InjectDepsMiddleware` (installed by `surface.New`) puts the server's
dependency set on the context; handlers pull it via `MustDepsFromContext`
(`pkg/windows/dependencies.go`, a typed wrapper over the toolkit generic). The `deps` argument passed
to `RegisterTools` is ignored by every handler — the context is the real path.
Receiving-middleware order, outermost first: **inject-deps → cache-hints → audit
→ telemetry → rug-pull → tool-policy**. Order matters; audit must see the call,
and policy must be innermost so nothing bypasses it.

**Install the whole chain in one `AddReceivingMiddleware` call** — that is what
`surface.Surface.InstallReceiving` (mcp-server-core) is for, and every entry
point goes through it. The SDK composes the middleware given to a *single*
call outermost-first, but each separate call wraps the chain built so far, so
adding them one at a time makes the **last** one outermost — silently reversing
the order. That inversion put the policy engine outside the audit layer, and a
refused call produced no `tool.call` entry at all. `TestReceivingMiddlewareRuns\
OutermostFirst` and `TestOuterMiddlewareObservesRefusedRequests` pin it, in core.

### Personas and toolsets

A persona (`toolsets.go:74-142`) is *only* a (toolset selection + read-only
stance + instructions text) preset over the one manifest. Adding a persona never
means adding tools. The IDs and memberships are identical to macos-mcp-server's
so a policy document means the same thing on both platforms.
`mcp-server-core/inventory` also supports an `InstructionsFunc` per toolset —
currently unused; don't assume it's wired.

## The security subsystem

A policy engine on the request path, plus an out-of-band kill switch. See
`docs/security-architecture.md` for the design and `docs/policy-config.md` for the
document schema. The policy engine, audit chain, rug-pull detection, kill switch
and egress proxy come from agentweave-harness; the wiring of them into a session
(`runtime.ProvisionEgress`, `runtime.ReceivingChain`, `runtime.TripFunc`, the
harness servant, the planner, evidence sealing) comes from
`mcp-server-core/runtime`; this repo supplies the Windows probes and actuators
(`internal/winmcp`) and the order in which `RunStdio` calls them.

**The guardrails packages live in the
[agentweave-harness](https://github.com/deploymenttheory/agentweave-harness)
module** (`guardrails/{signals,audit,hostmatch,policy,egress,enforce,watch,contain,status,evidence,export,plan,telemetry}`)
— extracted from this repo's former `internal/guardrails` so a separate harness
process can eventually own adjudication. This server imports them for its
standalone (in-process) stack; their layer table, acyclic-import rule and
package-level invariants are documented in that repo's CLAUDE.md, and their
package tests run in that repo's CI, not here. Everything below about how this
server *wires* them still applies. The generic wiring-level tests
(`TestReceivingMiddlewareRunsOutermostFirst`, …) now run in mcp-server-core; the
ones that pin this server's own choices (`TestServerDefaultPolicyIsAuditOnly`,
the egress delegation tests, the credential-exposure persona tests) stay here. When a change here needs a guardrails-package change, that
is a two-PR dance: harness PR + tag first, then bump the pin in go.mod.

Everything is configured by a JSON document — `--policy-config` is the only
security flag.

### Harness servant mode

When the agentweave-harness process spawns this server it sets
`AGENTWEAVE_CONTROL_PIPE` and `AGENTWEAVE_CONTROL_TOKEN` in the environment.
`runtime.HarnessAddress` detects that; `harnesslink.go` here supplies the
go-winio named-pipe dialer and `runtime.AttachHarness` authenticates with the
token (then RunStdio scrubs both vars, like every other secret env var) and
serves the harness through `runtime.HarnessServant`: `signal.evaluate` runs
registered guardrail checks **by declared id only**, `actuate` executes a
**closed rung set** (`runtime.BuildRungs`) mapped onto the same primitives the
local kill executor uses, and heartbeats/credential-events/audit-anchors are
pushed up. There is deliberately no generic execution verb on the channel — the
two properties `TestServantNeverExposesRunShell` and
`TestServantSignalEvaluateUsesDeclaredIdsOnly` pin, in core, so a harness
compromise cannot become RCE on this host. Channel loss cancels the run context
(`runtime.ErrHarnessChannelLost`), so the ordinary LIFO teardown — credential
cleanup included — runs exactly as on any other exit.

How much of the local stack runs depends on the `hello.ack`'s mode. Under an
**observe** ack the mode is additive: the server still wires its full
in-process guardrail stack. Under an **enforce** ack — which the harness sends
only once its own policy decider is actually installed on the proxy path — the
server sheds the duplicated layers: no local enforce/rug-pull/telemetry
middleware, no GuardrailStatus/Kill tools, no rug-pull baselines or recheck
(the harness fingerprints the manifest from the wire, where a tampered server
cannot vouch for itself). The local **audit** middleware stays in every mode —
this host's chain is the record of what the process actually served, kept so
the harness's account of the session is not the only one — as do the kill
executor and actuation rungs the harness drives. The seam is
`runtime.ReceivingChain`, pinned in core by
`TestHarnessModeInstallsNoLocalEnforcement`, `TestHarnessModeStillAuditsLocally`
and `TestObserveAckKeepsFullLocalStack`; Status/Kill registration and the baselines live in one `if` block in
`server.go` deliberately, so the pinned tool surface and the served tool
surface can never disagree. With no harness present `runtime.HarnessAddress()`
is empty and the server runs standalone unchanged.

In enforce mode the composed egress policy lives harness-side, so the server's
own `devicePolicy.Egress` is off and the local `provisionEgress` path does
nothing. The harness instead drives OS enforcement over the channel: an
`egress_apply` actuation carries the tier, app list, proxy port and harness
executable, and the server's egress rungs (`runtime.BuildRungs` over a fresh
`egress.WindowsEnforcer` from `newEnforcer`) install the firewall/WinINET,
stashing the undo in a `runtime.EgressRestoreHolder` that the explicit
`egress_restore` rung and the exit defer both reach exactly once.

When the ack announces an egress proxy (`egress_proxy_port` +
`egress_proxy_executable`) for a session whose **local** policy still has egress
enabled (observe mode with local egress), the server starts **no local egress
listener** — that is the only thing skipped. `Recover()` still runs on every start, the
elevation refusal still applies, and OS enforcement still installs, pointed
at the harness's port with the global-block allow rule naming the harness
executable (`runtime.ProvisionEgress` with the Windows enforcer plugged in by
`provisionEgress`; `TestHarnessModeSkipsLocalProxyOnlyWhenPortAnnounced` here
runs it with the real enforcer). The attach therefore
happens *before* egress provisioning in RunStdio, with the harness teardown
defers registered after the executor's Restore so the unwind keeps its
layering. Fail-closed holds across a harness death: the firewall stands while
the proxy dies, so traffic is cut rather than freed. The servant is a separate implementer of the wire contract — it
imports the public `wire` package but never the harness's internal transport, so
the pipe is dialed with go-winio directly (`dialHarness`). Servant wire-protocol
logic is tested over `net.Pipe` in core; note `net.Pipe` and the Windows control
pipe are both synchronous, so a test that has the servant send and the test read
must do so on separate goroutines or it deadlocks.

### Invariants that are easy to break

- **The default must never refuse.** `policy_default.json` applies whenever no
  document is given, so an enforcing default would start denying calls on devices
  that worked the day before. `TestDefaultPolicyIsAuditOnly` pins it, and
  `mode: audit` *caps* severity rather than skipping evaluation — the recorded
  `intended` verdict is what makes audit mode worth running.
- **Transparency is never conditional on containment.** Every verdict is audited,
  including allows and including in audit mode, and the `policy.decision` entry is
  written *before* any trip. A trigger that fires while its policy switch is off
  is still detected, logged and chained (`killswitch.disarmed` via `runtime.TripFunc`).
- **A report-only trip must not end the in-flight monitor.** `MonitorConfig.Stopped`
  gates loop exit and only a real trip sets it. Returning unconditionally after a
  trip would make disabling one trigger silently disable all monitoring.
- **The kill ladder's ordering is deliberate** (`killaction.go`): audit, banner and
  **seal** happen before any containment, and the recording is finalized before
  shutdown, or the forensic trail is lost. Don't reorder it.
- **`on_fail: kill` needs no second switch.** A rule saying it *is* the operator
  arming containment, in the same document. `kill.triggers` covers only the
  sources with no severity of their own — posture drift, rug-pull, heartbeat gap,
  sentinel. Don't add rule-derived kills to that block.
- **The agent-facing `Kill` tool is not an authoritative trigger.** It routes to
  `StopGracefully` unless the policy configures containment actions.
- **Refuse in the shape the method requires.** `deny` on `tools/call` is an
  `IsError` result with a nil Go error; on `resources/read` and `prompts/get` it is
  a JSON-RPC error, because those have no `IsError` envelope. `Engine.refuse`
  handles both — don't collapse them.

### The egress proxy: two orderings and a listener

The `egress` guardrails package is a loopback forward proxy admitting only the
domains `policy.EgressPolicy` declares. Three properties are load-bearing:

- **The allowlist is checked before the name is resolved.** A refused host must
  produce no DNS query, or the refusal itself becomes the outbound signal. This is
  the opposite of what caddyserver/forwardproxy does, and it is why we did not
  take that dependency.
- **Forbidden addresses are checked on the resolved answers, and the dial goes to
  the vetted address, not the name.** An allowed name resolving to loopback,
  RFC1918 or `169.254.169.254` is the bypass the allowlist exists to prevent, and
  re-resolving at dial time would reopen it.
- **It binds loopback only, asserted at the bind as well as at load.**
  `egress.requireLoopback` sits next to `net.Listen` so no future caller can
  construct a `Config` by hand and get a proxy the network can reach — the same
  reason the transport is stdio-only.

Egress defaults **off**, pinned by `TestDefaultPolicyIsAuditOnly`: a server that
began proxying traffic on upgrade, with no operator action, is the same class of
regression as one that began refusing tool calls. Per-request events go to `slog`
only — the audit chain gets periodic `egress.summary` aggregates and a capped
first-sighting record, because the chain is hashed and fsynced and a
host-rotating client must not be able to drive its length.

`Enforcement()` names the tier (`proxy-only`/`scoped`/`global`) and the startup
path warns when it is `proxy-only`. Keep that distinction visible: a proxy nothing
is forced through is not enforcement, and an operator must never read one as the
other.

Scoped enforcement installs one outbound-block `INetFwRule` per named
application, through `contain.NewFwPolicy`/`WithCOMThread` so there is one COM
path to the firewall. Three rules about it:

- **Protocol is ANY, never TCP.** QUIC is UDP; a TCP-only rule leaves HTTP/3 as
  an open path past the proxy. Windows rejects a port on an ANY rule, which is
  why none is set.
- **Missing elevation is fatal, not degraded.** Unlike the kill ladder, which
  skips-and-audits because half a containment beats none mid-incident, a policy
  naming `applications` without elevation refuses to start. Serving a weaker
  posture than the document describes is the failure mode being prevented.
- **Rule names are written down before any rule exists**
  (`%ProgramData%\WindowsMCP\egress-rules.json`). They cannot be re-derived —
  they come from an application list a later run may not have — and every start
  runs `Recover()` even when egress is now off, because rules outlive the
  process that made them.

`TestFirewallRuleObjectAcceptsEveryProperty` exercises the hand-declared
`HNetCfg.FWRule` CLSID and every `Put_*` against the real firewall, stopping
short of `Rules.Add` (the only step needing elevation) so it runs unprivileged
in CI. If you change a property, that test is what catches a wrong argument type
before an elevated machine does.

Global mode (`block_all_outbound`) flips the machine's default outbound action.
Four rules, all learned the hard way:

- **Allow rules go in before the default flips; restoring reverses it.** In the
  other order there is a window with no DNS and no DHCP, and a lease lost in
  that window does not come back when the rules arrive. On the way out, the
  default action is restored first so a process dying mid-teardown leaves a
  usable machine.
- **The exception set is not optional decoration.** Dropping `Dnscache` or
  `Dhcp` gives a machine with no network; dropping `NlaSvc` gives one where
  Windows reports "no internet" and applications stop trying rather than
  failing cleanly. `defaultExceptions()` documents why each entry exists, and
  `TestGlobalAllowRulesCoverTheMachineEssentials` makes removing one deliberate.
- **`Suspend()` must never restore.** The kill ladder's `IsolateNetwork` flips
  the same defaults, and explicit allows beat a blocked default — so containment
  needs those rules switched off. Restoring anything in `Finalize` would
  countermand the isolation just applied. Full teardown belongs to the exit
  defer, and a machine that reboots still contained is the right way to fail.
- **The state file is written before any mutation and read on every start**,
  even when egress is now disabled. It carries the saved per-profile action, not
  an assumption of `Allow`: an operator whose machine already blocked outbound
  must not have that silently undone by this server exiting.

The live global-block tests are gated behind `WINDOWS_MCP_GLOBAL_BLOCK_TEST=1`,
deliberately a different variable from the scoped tests' — running those must
never cut a machine off by accident.

### Cost and correctness

Signals are cached with a per-signal TTL because `dsregcmd`, WMI and `tpmtool`
cost hundreds of milliseconds each and a desktop session makes many small calls.
`ttl: 0` means live. Two things follow: the cache starts *unread* rather than
passing (a fresh-and-passing cache would admit the first calls without looking at
the device), and `signalCache.Refresh` returns nil even when a signal fails — it
runs as a monitor `VerifyFunc`, and a `VerifyFunc` error fires that check's kill
trigger, which would escalate every failure past the severity its policy assigned.

The core stays platform-agnostic behind `SystemProbe` / `HealthProbe` /
`SystemActuator` / `ToolIndex`, with `actuator_stub.go` for `!windows`, so the
engine is unit-testable with fakes and no Windows host. `internal/winmcp` supplies
the adapters. Keep new logic behind those interfaces.

Secrets for the tier-2 signals (Graph, remote may-run) come from environment
variables, never from flags or the policy document: argv is world-readable and a
policy is meant to be reviewable and checked in.

## Credentials — the never-read invariant

`internal/desktop/credentials.go` is the **only** place in the server that touches
a plaintext credential after it leaves the config file. The invariant: the agent
can *use* a secret but can never *read* one.

- No function in `internal/desktop` returns a secret. `readSecretUnits` returns
  UTF-16 code units, not a string, precisely so a refactor cannot hand one to a
  caller; `InjectCredential` converts them straight to keystrokes and zeroes the
  buffer. Only a coarse length band comes back — never a count, which would
  confirm a guessed value (`describeTyped`, `pkg/windows/credentials.go`).
- The `Credentials` tool has exactly three modes — `list`, `verify`, `inject` —
  and `TestCredentialsToolNeverReturnsSecrets` pins that set. **Do not add a
  `get`/`read` mode**: it would put plaintext into the model's context.
- `ToolDependencies.Credentials()` returns `[]toolkit.CredentialInfo`, which has
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

`"enforce_https": true` in the policy document refuses plaintext `http://`
targets. `mcp-server-core/toolkit/urlpolicy.go` owns the tool-layer policy; the guardrails
`signals` package (`remote.go`) applies it to the may-run endpoint via
`Env.EnforceHTTPS`. RunStdio copies the setting onto `Config` right after loading,
because it has to reach the tool dependencies and the guardrail `Env`, neither of
which carries a policy.

Two traps to preserve:

- **Compare schemes case-insensitively.** `url.Parse` keeps the caller's case and
  `HTTP://host` is a valid equivalent URL, so a `==` comparison is a trivial
  bypass. Use `strings.EqualFold` / `strings.ToLower`.
- **A URL-shaped value is a navigation.** `App`'s `name` is normally something like
  `notepad`, but `Start-Process http://example.com` opens the default browser.
  `toolkit.URLSchemeIfURL` exists to spot that, and requires an explicit `://` so a bare
  `example.com` or a file path is not mistaken for a URL.

When adding another URL entry point, gate it through `toolkit.EnforceHTTPSScheme` and
update the "Data exposure over plaintext HTTP" row of the threat-model table in
`docs/security-architecture.md`, which is where the Enforce HTTPS coverage is
recorded.

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

The required `.github/workflows/mcp-spec-compliance.yml` job runs on every PR.
It fails if a newer published MCP schema revision exists, then runs
`TestProductSpecGate` and the wire result tests against the latest vendored
schema. `CaptureSurface` uses the same `newSurface` constructor as `RunStdio`;
the core `surface` package records raw responses, validates each implemented
capability and definition, and probes safe product methods. Add a validator and
product probe whenever the server implements another MCP capability or result
shape. Do not publish a percentage of the full optional protocol surface.
The optional `conformance` build tag still provides an HTTP diagnostic host;
its fixtures are not part of the required verdict or released binary.

### What 2026-07-28 changed that this code owns

The SDK implements the wire; the gaps were in our layers, and they are load-bearing:

- `server/discover` is the canonical advertisement of capabilities and
  instructions, so `RugPull.DiscoverMiddleware` fingerprints it
  (`HashDiscover` = capabilities + instructions; **not** `supportedVersions`, which
  is transport-derived and differs legitimately between stdio and HTTP).
- `server.discover` and `subscriptions.listen` are audited. Without the first the
  chain holds no record that a client connected — there is no handshake any more.
- Neither `subscriptions/listen` nor `server/discover` is rate-limited. The
  circuit breaker they were once counted against no longer exists — rate limits
  live in the policy document and are spent inside `Engine.Evaluate`, which only
  the three decidable methods reach. Both are audited, and the client-supplied
  text each carries is clipped, because an unthrottled method whose payload the
  client chooses is otherwise a way to grow the chain without bound.
- A blocked non-tool method returns a **JSON-RPC error** (`blockedError`), not an
  `IsError` result. The `IsError` convention is tools-only: answering a
  `resources/read` with a `CallToolResult` puts the wrong envelope on the wire.
- `surface.CacheHintsMiddleware` sets `ttlMs`/`cacheScope` on all six cacheable results.
  The SDK's `"public"` default is wrong here — a `resources/read` returns one
  user's desktop, and the manifest depends on this session's persona and toolsets.

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
`surface.PinnedCapabilities()` declares all four explicitly with `ListChanged`
false — keep it that way.

### Guardrails cover the new methods

`resources/read` and `prompts/get` are data-egress paths, so they are audited
(`resource.read`, `prompt.get`, arguments digested never raw), both are decided by
the policy engine as read-only subjects (so a resource exposing the same state as
a tool is not a way around the rule covering that tool), and both
manifests are rug-pull fingerprinted via `HashPrompts`/`HashResources`. A surface
with no pinned baseline is skipped rather than treated as drift.

## Build tags

Everything is `//go:build windows && (amd64 || arm64)` **except** the
deliberately platform-agnostic files: `pkg/windows/{toolsets,psscript}.go` and
`internal/psdata`. The rest of the platform-agnostic code — the inventory engine,
the toolkit, the schema loader, the conformance reporting — lives in
mcp-server-core, and the guardrails packages in agentweave-harness; both have CI
legs that keep that code runnable without a Windows host. Preserve that split.

There is one extra tag: **`conformance`**. It adds the loopback HTTP host and the
conformance-suite fixtures and nothing else, and `go build ./...` must never
compile it. Build and test that side explicitly:

```powershell
go build -tags conformance ./...
go test -tags conformance ./internal/winmcp/ -count=1
```

## Notable gotchas

- **stdout is reserved** for the MCP stdio transport. Logs go to stderr or a file
  (`runtime.NewLogger`); the audit `stderr` destination writes `AUDIT {json}`
  lines to stderr for the same reason.
- **`winenv.go` exists because MCP hosts strip the environment.** It rebuilds
  `PATH` and friends from the registry (merging, not overwriting, PATH). Resolve
  executables with `resolvePwsh` / `lookPathIn` and pass `powerShellEnv()` to any
  `exec.Cmd` — don't rely on the inherited environment.
- **PowerShell is invoked via `-EncodedCommand`** (base64 UTF-16LE,
  `powershell.go:29`), which removes all shell-quoting concerns. Toasts
  specifically need Windows PowerShell 5.1 (`RunWindowsPowerShell`) because
  pwsh 7 does not expose the WinRT APIs.
- `surface.PinnedCapabilities()` sets `Tools = &mcp.ToolCapabilities{}`, which deliberately
  suppresses `tools/list_changed` — a silent manifest change is exactly what the
  rug-pull detector exists to catch.
