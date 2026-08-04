# Security assessment: claims versus implementation

**Date:** 2026-08-04 · **Commit:** `4f68c58` · **Method:** source review against the
security documentation. No dynamic testing, no live device, no adversarial harness.

## What this is

This document asks one question adversarially: **where does the implementation
diverge from what the documentation claims, and which real gaps are recorded
nowhere?**

It is deliberately not a balanced summary. The premise is a reader who has read
`docs/security-architecture.md`, believes it, and is deciding whether to deploy —
and who deserves to know every place that belief would be misplaced. Findings are
argued against the documentation's own words rather than described in the abstract,
because a gap the docs already name honestly is a different kind of problem from one
they paper over.

Four registers:

| Register | Contents |
|---|---|
| **A** | Real gaps documented nowhere — the answer to the question asked |
| **B** | Claims the code contradicts |
| **C** | Stale or inconsistent documentation |
| **D** | What held up under review |

Every finding carries a `file:line` reference, verified against the tree at the
commit above. Line numbers drift; the appendix gives commands that re-locate each
one by content.

## Status

**Every finding in registers A, B and C has been remediated**, in the PR that
added this document. The findings are left stated in the present tense as they
were written, because the argument for each fix is the finding itself and a
register rewritten into the past tense stops being checkable. What changed:

| Finding | Fix |
|---|---|
| A1 destructive annotation | `DestructiveHint` added to `Invoke`, `Click`, `Scroll`, `MultiSelect`, `Clipboard`, `Notification`, `Recording`. `Move` deliberately left out, with the reasoning recorded. `TestEveryWriteToolIsAnnotatedDestructive` inverts the tripwire to deny-by-default |
| A2 clipboard | Covered by A1; `Clipboard` is now behind any destructive rule |
| A3 Scrape SSRF | Uses `hostmatch.ForbiddenAddr`; the dial goes to the vetted address, closing the rebinding window (also roadmap S1) |
| A4 `completion/complete` | Audited and policy-decided; the typed prefix is digested, not recorded |
| A5 `subscriptions/listen` | Policy-decided as a read-only data-egress subject |
| A6 posture drift | Arming it without a `scope: "startup"` rule is refused at load |
| A7 status token | `status_token_env` added; inline `status_token` deprecated and warned |
| A8 egress auth | An `auth_token_env` naming an empty variable is now fatal, not a warning |
| A9 malformed params | Refused and audited `policy.undecidable` instead of passing undecided |
| A10 digest salt | Logs when it degrades; `DigestIsUnsalted()` exposes it |
| A11 run-context | `RunContext.TokenUnread` distinguishes a failed read from an answer; reports `Error` |
| A12 proxy challenge | Advertises `Bearer`; RFC 7617 `Basic` accepted properly |
| B1–B5, C | Documentation corrected; the threat-model table gained a **Coverage** column |

Two things this PR did **not** change, both out of its scope: roadmap items S2–S11
remain open and are unaffected, and the two pre-existing `go vet` warnings in
`internal/desktop/journeyhook_windows.go` are untouched.

## Dynamic validation (2026-08-04)

The registers below were produced by reading code. That has a specific weakness:
the tests written from a source review encode the same model of the system the
review used, so green tests confirm the code matches the reading, not that either
matches Windows.

So the fixes were then driven against a disposable Hyper-V guest — the untagged
product binary, full guardrails, spoken to as a real MCP client over stdio, in an
interactive desktop session.

**Confirmed working on a live system:** the destructive annotations (`Clipboard`,
`Invoke`, `Click` refused by an `annotation: destructive` rule, while `Move` — the
deliberate exemption — was allowed and moved the cursor); `completion.complete`
audited with the typed prefix digested; `status_token_env` fatal when unset and
the inline form warning; the proxy advertising `Bearer` and accepting RFC 7617
`Basic`; `posture_drift` refused without a startup rule; `Scrape` fetching real
hosts while refusing internal ones through real DNS; the chain keyed only for
file/directory destinations; in-place and sealed-file truncation both detected;
the credential ACL and toolset-exposure refusals; and the kill ladder sealing the
chain, auditing `killaction.done{isolate}` when elevated and
`killaction.skipped{"why":"not elevated"}` when not.

**The credential invariant, tested the only way that means anything:** with
Notepad focused and the agent having just typed into it, injection into that same
unmasked field was refused. That check cannot run without a desktop, and the
behaviour it protects was a real vulnerability before #73.

**Four findings no source review had produced**, all fixed or recorded in PR #77:
an unsealed session's truncated tail verified clean and silent (now `UNSEALED` +
`--strict`; detection itself is roadmap S12); the firewall restore materialised an
explicit `Allow` where nothing had been configured, because
`Get_DefaultOutboundAction` reports `ALLOW` for an absent value (now restored to
absent); a UTF-8 BOM — what PowerShell 5.1 and Notepad write by default — made a
policy unparseable with a message naming neither the file nor the cause; and a
rule naming a tool does not reach `completion/complete`, so credential *names*
stayed enumerable under a policy that refused every `Credentials` mode (documented;
schema work is roadmap S14).

**One thing remains unresolved and is the reason `isolate` should not be trusted
yet.** The ladder audits `killaction.done{isolate}`, and driving
`Put_DefaultOutboundAction(BLOCK)` directly does take effect and persist — but a
2,789-sample poll at ~3 ms resolution spanning a real trip never observed the
outbound default leaving `Allow`. Roadmap S13.

**Not validated at all:** session recording, the journey recorder's password
redaction (roadmap S4), and injection into a genuine masked field (the positive
case).

---

**Standing caveat.** `SECURITY.md:28-41` puts unsandboxed tool access and spoofable
local signals out of scope, and this assessment honours that. Nothing below amounts
to "the PowerShell tool can run PowerShell". The findings are about controls behaving
differently from their description.

---

## Register A — Real gaps documented nowhere

Ranked by what an untrusted model driving the **default** surface could do with them.

### A1. The destructive annotation misses most of the input-injection surface

**New finding. Highest severity in this document.**

Eight tools carry no `DestructiveHint`:

| Tool | Location | Reach |
|---|---|---|
| `Invoke` | `pkg/windows/actions.go:26` | UIA `Invoke`/`SetValue`/`Toggle`/`Select` |
| `Click` | `pkg/windows/interaction.go:101` | mouse injection |
| `Scroll` | `pkg/windows/interaction.go:200` | wheel injection |
| `Move` | `pkg/windows/interaction.go:241` | cursor injection |
| `MultiSelect` | `pkg/windows/multi.go:45` | *n* ctrl-clicks |
| `Clipboard` | `pkg/windows/clipboard.go:22` | read and overwrite the clipboard |
| `Notification` | `pkg/windows/notification.go:30` | toast under an arbitrary AppUserModelID |
| `Recording` | `pkg/windows/recording.go:27` | appends model text to the session file |

All eight are in `Default: true` toolsets (`pkg/windows/toolsets.go:14,21,28,35`), so
every persona carries them.

`CLAUDE.md:140` states the stakes exactly: the hint "is load-bearing metadata now, not
documentation." Every shipped enforcing policy keys its controls on
`annotation: destructive` — the hardware-posture rule, the `require_plan` gate and the
destructive-burst rate limit (`policy/examples/enterprise.json:31,51,83`;
`secure.json:31`; `locked-down.json:37,45`). These eight tools are therefore outside
**every** control those documents express.

What makes this more than an oversight is the direction the server steers the model.
The `business-user` persona's instructions — injected by this server as its MCP
instructions — say:

> "Prefer the UIA actions (Invoke/SetValue) over raw `Click`/`Type` where available:
> they are more reliable and do not depend on window focus."
> — `pkg/windows/toolsets.go:176-177`

`Type` carries `DestructiveHint` (`interaction.go:149`). `Invoke` does not. The server
instructs the model to move from the gated primitive to the ungated one that does the
same work. Under `enterprise.json`, filling and submitting a form via `Type` needs
`require_plan` and spends burst budget; via `Invoke` it needs neither.

The tripwire that exists to prevent this misses it.
`TestExecutionPrimitivesAreAnnotatedDestructive` (`pkg/windows/tools_test.go:272-292`)
checks `App`, `Type`, `Shortcut`, `MultiEdit` and `Credentials`. Its own rationale is
that these are "universal write primitives" whose absence from the annotation meant a
destructive rule "silently did not cover them" (`tools_test.go:265-271`). That argument
covers `Invoke` and `Click` verbatim, and neither is in the map.

`Recording` has a near-miss of its own: `TestRecordingIsNotReadOnly`
(`tools_test.go:298-311`) fixes the read-only half of the problem and leaves the
destructive half open, so `mode=mark` writes model-supplied text into the session
evidence file outside every gate.

**Nothing in the documentation names this.** `docs/policy-config.md:210-220` lists what
policy does not cover — `GuardrailStatus` and `Kill` — and does not mention that most
of the input surface is unmatched by the annotation every example uses.

### A2. `Clipboard mode=get` is an ungated read channel on the default surface

**New finding.**

`internal/desktop/credentials.go:340-342` names the clipboard as one of the three
things the never-read invariant exists to defeat: typing into an unmasked control
"would put it on screen and in reach of Screenshot, GetText and the **clipboard**."

The `Clipboard` tool is in the default `system` toolset, un-annotated (A1), and
`mode=get` returns whatever was last placed there — including by a password manager
the agent never touched.

This is not a breach of the credential invariant, which holds as written (see D). It
is a flanking path around the reasoning behind it, and the credentials documentation
presents the guarantee without naming it. `docs/credentials.md:166-169` records the
process-memory residual and stops there.

### A3. `Scrape` does not reuse the hardened address check this repo already ships

**Sharpens roadmap S1**, which records only half of it.

`validateScrapeURL` (`pkg/windows/scrape.go:106-115`) rolls its own check:

```go
for _, ip := range ips {
    if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
```

`hostmatch.ForbiddenAddr` (`internal/guardrails/hostmatch/private.go:38-115`) — used by
the egress proxy, fuzz-tested, and importable from `pkg/windows` today — additionally
refuses CGNAT `100.64.0.0/10`, IANA special-purpose ranges, and IPv4 embedded in IPv6
via NAT64 (`64:ff9b::/96`), 6to4 and `::/96`, by recursing into the embedded address.
`Scrape`'s check does not: `To4()` returns nil for a NAT64-embedded address, so
`64:ff9b::a9fe:a9fe` passes every one of those four tests.

Roadmap S1 documents the *re-resolution* half — `net.LookupIP` at `scrape.go:106`, then
`client.Do` resolving the name again at `:152`, the classic rebinding window. The
*weaker predicate* half is recorded nowhere, and it is the easier of the two to fix:
the correct implementation is one import away, and the repo's own architecture notes
(`CLAUDE.md:246-249`) present "check the resolved answers, dial the vetted address" as
a property of the system rather than of one package.

### A4. `completion/complete` is neither audited nor policy-decided

**New finding.**

The method appears in neither switch:

- `enforce.subjectFor` (`internal/guardrails/enforce/enforce.go:356-381`) handles
  `tools/call`, `resources/read`, `prompts/get`; its `default` arm returns
  `(Subject{}, false)`, so everything else proceeds undecided.
- `AuditLog.Middleware` (`internal/guardrails/audit/audit.go:329-355`) handles those
  three plus `server/discover` and `subscriptions/listen`.

The handler returns credential **names** into the model's context
(`internal/winmcp/completion.go:104-118`), along with persona, toolset and tool names.
The handler's comment is careful that it "never sources a credential secret"
(`completion.go:25-27`) — correct, and beside the point: this is a data-returning
method that leaves no record it was called.

`CLAUDE.md:455-467` enumerates which 2026-07-28 methods are audited and argues each
case. `completion/complete` is absent without comment, which reads as coverage rather
than omission.

### A5. `subscriptions/listen` is audited but never adjudicated

**New finding.**

The audit layer's own comment describes it as "a standing data-egress path and the
longest-lived one the server has" (`audit.go:320-323`).

`resources/read` and `prompts/get` were brought under the policy engine on exactly that
reasoning — `enforce.go:383-392` argues that a resource exposing the same desktop state
as a tool "must not be a way around the rule covering that tool." The same argument
applies to a long-lived subscription stream and is not applied. `subscriptions/listen`
reaches the `default` arm of `subjectFor` and proceeds undecided.

This may well be the right call — the SDK's subscription model may leave nothing
useful to decide. The gap is that the reasoning is written down for two methods and
silently not extended to the third.

### A6. Posture-drift detection is inert without an operator-authored startup rule

**New finding.**

The in-flight monitor's drift path evaluates one subject:

```go
v := engine.Evaluate(c, policy.StartupSubject())   // internal/winmcp/server.go:572
```

`Engine.matches` pairs a startup subject only with rules carrying `scope: "startup"`
(`internal/guardrails/policy/engine.go:386-390`); a rule's scope defaults to `call`
(`policyconfig.go:347-348, 386`). The other route to the trigger, `engine.Refresh`
wired as a `VerifyFunc` at `server.go:552-556`, returns nil unconditionally by design
(`signalcache.go:142-164`) — correct in itself, and documented at
`security-architecture.md:166-168`, but it means nothing else can fire the trigger.

So drift detection depends entirely on the policy containing at least one
startup-scope rule. All four enforcing examples do
(`egress.json:17`, `enterprise.json:19`, `locked-down.json:19`, `secure.json:25`).
`internal/guardrails/policy/policy_default.json` does not — its single rule matches
`toolset: "*"` at call scope. An operator who arms `posture_drift` in a policy without
a startup rule gets a monitor that runs, logs, and can never trip. Nothing warns them:
policy validation does not require a startup rule when a drift trigger is armed.

The threat-model row states the mechanism unconditionally:

> **Silent posture drift** … In-flight monitor re-evaluates live posture every
> interval → audited always, kill on drift when armed
> — `docs/security-architecture.md:441`

"when armed" qualifies the *containment*. It does not hint that the *detection* has a
second, undocumented precondition.

### A7. `transparency.status_token` is the one trigger credential not held in an environment variable

**New finding.** Conditional — the status endpoint is off by default
(`docs/monitoring.md:15`).

Three facts compose:

1. The token lives in the policy JSON in cleartext
   (`internal/guardrails/policy/policyconfig.go:481`).
2. The policy document is registered as a protected path with `denyRead=false`:
   `NewProtectedPath(cfg.PolicyConfig, "the policy document", false, false, true)`
   — `internal/winmcp/toolsurface.go:51`, signature at `pkg/windows/dependencies.go:75`.
3. `POST /revoke` trips the kill switch and runs the full containment ladder
   (`internal/guardrails/status/status.go:166-174`).

With `filesystem` served, the agent reads the token directly. With `shell` served, it
bypasses `ProtectedPath` altogether (roadmap S8) and reaches the file anyway. Either
way it can then isolate the network, lock the workstation and abort the session.

This is the escalation the design closes everywhere else, deliberately and with the
reasoning written down. The kill sentinel was hardened to a per-session random token
the agent cannot write (`internal/guardrails/contain/sentinel.go:13-31`) after
"authenticated by its own existence" turned one file write into a containment trigger —
recorded in the roadmap's Delivered list. The agent-facing `Kill` tool routes to
`StopGracefully` precisely so self-triggering is not a denial-of-service vector
(`security-architecture.md:347-354`).

Every other trigger credential is an environment secret — `WINDOWS_MCP_AUDIT_KEY`,
`_APPROVAL_KEY`, `_GRAPH_CLIENT_SECRET`, `_REMOTE_POLICY_TOKEN` — and egress even
takes the *name* of a variable rather than a value, on the stated grounds that "the
document is meant to be reviewable and checked in" (`docs/egress.md:98-100`). The
status token is the exception to a rule the docs state absolutely
(`README.md:350-369`, `security-architecture.md:461-465`), and the exception is not
noted.

### A8. The egress proxy serves unauthenticated when `auth_token_env` names an empty variable

**New finding.**

```go
token = os.Getenv(cfg.AuthTokenEnv)
if token == "" {
    logger.Warn("egress auth_token_env names an empty variable; the proxy will not require a credential", ...)
}
```
— `internal/winmcp/egress.go:67-72`, with `proxy.authorized` returning true for an
empty configured token (`internal/guardrails/egress/proxy.go:106-109`).

Six lines below that warning, the missing-elevation case refuses to start — with a
comment that makes the argument for us:

> "an operator whose document says these applications cannot bypass the proxy must
> never get a server where they silently can."
> — `internal/winmcp/egress.go:74-79`

An operator whose document says the proxy requires a credential is in the identical
position, and gets a warning on stderr instead. The typo case is realistic: a renamed
variable, a service account whose environment was not updated, a scrubbed variable read
in the wrong order.

`docs/policy-config.md:574` covers the adjacent case — "Any local process can use it
unless you set `auth_token_env`" — which reads as reassurance that setting it closes
the hole.

### A9. A malformed params object passes with no verdict and no audit record

**New finding.**

`subjectFor` returns `decidable=false` when the params type assertion fails
(`enforce.go:359-361, 366-368, 373-375`), and the middleware then calls `next` with no
decision recorded. The audit middleware type-asserts identically
(`audit.go:331, 339, 343`), so both layers fall silent on the same input.

This contradicts the transparency claim directly:

> "Every verdict is written to the audit chain first — including allows, and including
> in audit mode — so the record exists before anything acts on it."
> — `docs/security-architecture.md:62-63`

Narrow: it needs the SDK to hand a handler a params object of an unexpected concrete
type, which is not obviously reachable from the wire. But the shape of the failure —
unexpected input producing a permit with no record — is the one the architecture
argues cannot occur, and `SECURITY.md:43-57` puts "silently breaking the chain" in
scope.

### A10. `digestSalt` degrades to unsalted SHA-256 with no log line

**New finding, low severity.**

`internal/guardrails/audit/audit.go:473-493`: the per-process salt is minted once, and
if `rand.Read` fails, `digestSalt` returns nil and `digestBytes` silently falls back to
an unsalted digest. The comment defends continuing rather than failing, which is
reasonable. What is missing is a log line: the property that argument digests resist a
dictionary attack can disappear with no operator-visible signal.

Contrast `resolveAuditKey` (`internal/winmcp/auditkey.go:56-63`), which handles the
same class of failure and does warn.

### A11. `run-context` passes when the process-token read fails

**New finding.** This is the only signal the shipped default policy requires.

`internal/guardrails/signals/runcontext_windows.go:28-32` leaves `IsSystem` and
`Elevated` at their zero values when `OpenProcessToken` fails; `tokenIsSystem` and
`tokenIsElevated` likewise return false on a `GetTokenInformation` failure (`:55-56,
:64-65`). `IsInteractiveUser()` is then true whenever `SessionID != 0`
(`signals/guardrail.go:54`).

So an error reading the process token produces a **pass** on the one check the default
policy performs. `security-architecture.md:24-25` is candid that local signals are
"auditable defense-in-depth, not a hard boundary" — that covers spoofing, not
fail-open on error. Elsewhere the codebase takes the opposite direction deliberately:
a signal that errors is scored at the rule's full severity (`policy/engine.go:308-318`).

### A12. The proxy advertises an authentication scheme it cannot accept

**New finding, minor — interop, not bypass.**

The 407 sets `Proxy-Authenticate: Basic realm="windows-mcp-egress"`
(`egress/proxy.go:92`), but `authorized` strips the `Basic ` prefix and compares the
remainder to the raw token (`:110-113`). A client implementing RFC 7617 sends
base64(`user:token`) and can never match. The documented `Bearer` form works
(`docs/egress.md:104`), so this bites only a client that follows the challenge.

---

## Register B — Claims the code contradicts

### B1. "The chain is keyed by default" — the shipped default is unkeyed

**The single most consequential documentation error in the repository.**

> "The chain is keyed by default (generated on first use, or `WINDOWS_MCP_AUDIT_KEY`),
> and the session manifest that pins each head is MAC'd under the same key, so a record
> cannot be rewritten without it."
> — `docs/security-architecture.md:442`, the *Log tampering / gaps* threat row

The chain to walk:

1. The shipped default sets `"audit_destination": "stderr"`
   (`internal/guardrails/policy/policy_default.json:30`).
2. `resolveAuditKey` finds no `WINDOWS_MCP_AUDIT_KEY` and calls `auditKeyDir`
   (`internal/winmcp/auditkey.go:38-44`).
3. `auditKeyDir` returns `""` for a `stderr` destination — "there is no file to
   protect, and nowhere beside it to keep one" (`auditkey.go:76-82`).
4. `resolveAuditKey` returns nil. The chain is **unkeyed**.

Auto-generation is real and works — but only once an operator configures a file or
directory destination. Out of the box it does not apply.

Three other documents state this correctly:

- `README.md:363` — "HMAC key that seals the audit chain (absent → unkeyed)"
- `docs/monitoring.md:164` — "With no key set the chain is unkeyed — the default"
- `docs/monitoring.md:250-251` — "Unkeyed and un-anchored — the default — the chain is
  tamper-*evident* against accident and process death, not tamper-*proof* against a
  local admin"

`docs/security-architecture.md` is the outlier, and it is the outlier in the row a
reader consults to decide exactly this. The gap between the two readings is the gap
between "an attacker who edits the log is detected" and "an attacker who edits the log
recomputes the hashes and is not." That is also the difference between a finding in
scope under `SECURITY.md:43-49` and one out of it.

### B2. "`Credentials` is not annotated destructive" — it is

> "`Credentials` is **not** annotated destructive … A rate limit or rule matching
> `annotation: destructive` therefore does **not** cover it. Match it by name … if you
> want to gate it."
> — `docs/credentials.md:161-164`

`pkg/windows/credentials.go:27,45` sets `DestructiveHint`, with a comment recording
that this doc's counterpart once had it backwards:

> "Destructive so rules and rate limits matching that annotation cover credential
> injection. docs/security-architecture.md claimed they did; without the hint they did
> not, and enterprise.json's require_plan gate missed it too."

The fix landed; `docs/credentials.md` was not updated with it. The error is safe in
direction — an operator following it writes a redundant by-name rule — but it is wrong
about the one tool where rule authors most need to be right, and it now contradicts
`security-architecture.md:416`, which is correct.

### B3. The threat model's egress residual omits two known exceptions

The *Egress to unapproved destinations* row (`docs/security-architecture.md:445`) names
two honest exceptions to proxy coverage: `Network`'s `test` mode and `Package`. It does
not name:

- **`FileSystem` over UNC.** The tool's own annotation comment says it: "a UNC path
  reads from or writes to another host, which is network egress outside the proxy and
  the allowlist" (`pkg/windows/filesystem.go:83-84`). Roadmap **S9** records it.
- **`Scrape`.** Roadmap **S1**, plus A3 above.

This matters more than a normal omission because `CLAUDE.md:387-390` designates that
table as the register of record:

> "When adding another URL entry point, gate it through `enforceHTTPSScheme` and update
> the 'Data exposure over plaintext HTTP' row of the threat-model table in
> `docs/security-architecture.md`, **which is where the Enforce HTTPS coverage is
> recorded**."

Two exceptions the project knows about are absent from the place the project nominates
for recording them. The roadmap carries them, but a roadmap is a work list, not a
coverage statement, and the reader of the threat model has no reason to consult it.

### B4. Two accounts of what `inject` reports

- `security-architecture.md:443` — "reports only a coarse length band, **never a
  count**"
- `CLAUDE.md:345` and `docs/credentials.md:143-144` — "Only the character count comes
  back"

The code bands: `describeTyped` returns "nothing was typed" / "a short secret" / "a
medium-length secret" / "a long secret" (`pkg/windows/credentials.go:255-267`). The
threat-model row is right; the other two are stale in the safe direction — they
understate a hardening that shipped.

### B5. `SECURITY.md` scopes a control that no longer exists

`SECURITY.md:46` lists "the circuit breaker" among the controls whose bypass is in
scope for a report. `CLAUDE.md:462-464`: "The circuit breaker they were once counted
against no longer exists — rate limits live in the policy document." A researcher
reading the vulnerability-disclosure policy is pointed at a mechanism that is not
there.

---

## Register C — Stale or inconsistent documentation

Low severity individually. Listed because the pattern — several documents drifting
from a moving codebase in the same direction — is what lets B-register errors survive.

| Claim | Source | Actual |
|---|---|---|
| "34 tools across 12 toolsets" | `README.md:77` | **35** tools (`AllTools()`, pinned at `pkg/windows/tools_test.go:56`), **13** toolsets (`toolsets.go:12-107`), plus `GuardrailStatus` and `Kill` served outside the inventory |
| "Ten toolsets. Four are on by default" | `docs/toolsets-and-personas.md:16` | 13 toolsets; the "four by default" half is right (`toolsets.go:14,21,28,35`) |
| "All 27 inventory tools use `NewToolFromHandler`" | `CLAUDE.md:99` | 35 |
| "five starting points" / "five starting-point policy documents" | `README.md:263`, `docs/policy-config.md:588`, `docs/README.md:56` | **six** — `dual-control.json` is uncounted in all three |
| `on_fail` table lists `allow`/`warn`/`deny`/`kill` | `README.md:233-238` | omits `hold`, the verdict behind the entire dual-control feature (`docs/policy-config.md:27-33`) |
| `Registry`/`ScheduledTask` in the default `system` toolset | `README.md:108`, `docs/toolsets-and-personas.md:46-54` | non-default `system-admin` (`toolsets.go:46`) — as `README.md:289` correctly states two hundred lines later |
| "plan-and-apply (on the roadmap) will let the whole plan be reviewed" | `docs/deployment-decision.md:94-95` | shipped (`docs/plan-and-apply.md`, `pkg/windows/plantools.go`) |
| "This project has not yet cut a tagged release" | `SECURITY.md:24` | tags through 1.2.0 (`ce8e241`) |

### The structural cause

`docs/security-architecture.md`'s threat-model table (`:435-445`) has **two** columns:
`Threat` and `Mechanism`. There is no status or coverage column anywhere in it. Every
qualification lives as prose inside the mechanism cell — "when armed", "**Residual:**",
"does **not** intercept", "an honest exception".

The prose is genuinely careful. But a reader skimming a two-column threat table reads
the second column as *what is done*, and the conditions dissolve into it. That is the
mechanism by which B1 ("keyed by default", true only with a non-default destination),
A6 ("re-evaluates live posture", true only with a startup rule) and B3 (two exceptions
missing) all read as delivered coverage.

`README.md:285-291` gets this right with four columns and an explicit **Residual risk**
column. The architecture doc's table is the one CLAUDE.md nominates as the register of
record, and it is the weaker instrument.

---

## Register D — What held up

Reviewed and found sound. This register exists so the rest is read as an audit rather
than a hit list — and because several of these are genuinely stronger than comparable
implementations.

- **Middleware ordering and its pinning tests.** The single-`AddReceivingMiddleware`
  requirement (`internal/winmcp/surface.go:64-81`) is correct, non-obvious, and pinned
  by two tests. The historical inversion it prevents — policy outside audit, refused
  calls producing no record — is disclosed rather than buried.
- **PowerShell argument binding.** `internal/psdata` base64-binds every model-supplied
  value (`psdata.go:46-65`), and `-EncodedCommand` carries the script
  (`internal/desktop/powershell.go:80-84`). I traced every shell-touching tool —
  `registry.go`, `scheduledtask.go`, `eventlog.go`, `network.go`, `notification.go`,
  `package.go`, `app.go` — and found no interpolation of a model string into a script
  body. The Unicode-quote escape that produced the disclosed RCE is closed at the root
  rather than patched.
- **`hostmatch.ForbiddenAddr`.** Recursion through NAT64, 6to4 and `::/96` embedded
  IPv4 (`private.go:47-51, 101-115`) is more thorough than most SSRF guards. Which is
  what makes A3 a reuse failure rather than a knowledge gap.
- **The proxy's two orderings.** Allowlist before DNS (`egress/proxy.go:327-329`) and
  dial to the vetted address rather than the name (`:247-250, 391-401`) are both
  correct and both load-bearing, exactly as documented.
- **`Engine.refuse`'s two shapes** — `IsError` for `tools/call`, JSON-RPC error for the
  other two (`enforce.go:182-194`), avoiding the spec-reserved code range.
- **The never-read credential invariant, in Go.** `readSecretUnits` is unexported, has
  exactly one caller, and returns a count (`internal/desktop/credentials.go:357-369`).
  No path returns plaintext. `requireMaskedFocus` fails closed on every error branch
  (`:318-345`).
- **`enforce.awaitApproval` fails closed on a nil approver** (`enforce.go:212-227`), so
  the weaker conformance-host wiring cannot silently admit held calls.
- **`StatusServer.Start` refuses to bind without a token** at the listener, not only at
  policy load (`status/status.go:92-94`) — so a hand-built config cannot produce an
  unauthenticated kill endpoint. Note this sits alongside A7: the endpoint is
  well-defended and the key to it is in a readable file.
- **The kill ladder's ordering.** Audit, banner and seal before containment; recording
  finalized before shutdown; a `recover()` that still finalizes on panic mid-ladder
  (`contain/killaction.go:103-201`).
- **The roadmap itself.** S1–S11 are real findings recorded plainly, several of them
  unflattering. The Delivered list discloses five historical vulnerabilities including
  a full RCE from read-only tools. This is well above the norm and should be said.

---

## Summary

**Twelve findings recorded nowhere** (Register A), of which A1 is the one to act on
first: eight tools on the default surface — including the one the server's own
instructions tell the model to prefer — sit outside every control the shipped policies
express, and the test written to prevent exactly this omits them.

**Five contradicted claims** (Register B), of which B1 is the one to correct first:
`docs/security-architecture.md` tells operators the audit chain is keyed by default
when the shipped default is unkeyed, and three other documents say so correctly.

**Eight stale claims** (Register C) and one structural cause: the threat-model table
has no status column, so conditional coverage reads as delivered coverage.

Two observations on the shape of all this. First, most Register A findings are not
missing controls but **controls whose reasoning was written down once and not extended**
— audit covers five methods and the sixth was never argued about (A4); two data-egress
methods are adjudicated and the third is not (A5); egress refuses to degrade on
elevation and does degrade on authentication (A8). The design instinct is right; its
application is uneven, and the docs describe the instinct.

Second, the honesty gradient runs the wrong way. The roadmap is candid to a fault; the
architecture document, which is what an evaluating reader actually reads and which
`CLAUDE.md` designates as the coverage register, carries B1, B3 and B4. Whatever else
changes, that document should be the one held to the highest standard, not the lowest.

If a single next step is wanted: this document is a usable brief for the external
penetration test in roadmap C.1.4 — A1, A2 and A7 are directly testable by an agent in
the model's seat, and B1 is verifiable in one command.

---

## Appendix: re-verifying these findings

Line numbers drift. Each finding is re-locatable by content:

```powershell
# A1 — tools with no DestructiveHint
Select-String -Path pkg\windows\*.go -Pattern "ToolAnnotations" -Context 0,4 |
  Select-String -NotMatch "DestructiveHint"

# A1 — what the tripwire actually covers
Select-String -Path pkg\windows\tools_test.go -Pattern "TestExecutionPrimitivesAreAnnotatedDestructive" -Context 0,12

# A4/A5 — methods each layer handles
Select-String -Path internal\guardrails\enforce\enforce.go -Pattern "case method|default:"
Select-String -Path internal\guardrails\audit\audit.go -Pattern 'case "'

# A6 — startup rules present per policy
Select-String -Path policy\examples\*.json,internal\guardrails\policy\policy_default.json -Pattern '"scope"'

# A7 — the policy document's read protection
Select-String -Path internal\winmcp\toolsurface.go -Pattern "PolicyConfig"

# B1 — the four steps, in order
Select-String -Path internal\guardrails\policy\policy_default.json -Pattern "audit_destination"
Select-String -Path internal\winmcp\auditkey.go -Pattern "func resolveAuditKey|func auditKeyDir" -Context 0,10

# C — authoritative counts
Select-String -Path pkg\windows\tools_test.go -Pattern "const want"       # tools: 35
(Get-ChildItem policy\examples\*.json).Count                              # examples: 6
# Toolsets: 13. `Toolsets` and `Personas` share the ID field, so count the
# former only -- a bare "ID:" grep returns 16.
Select-String -Path pkg\windows\toolsets.go -Pattern "^var (Toolsets|Personas)","^\s+ID:"
```
