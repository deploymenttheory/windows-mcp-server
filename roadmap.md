# windows-mcp-server — Roadmap

**Repo:** `github.com/deploymenttheory/windows-mcp-server`

Work is themed **Now**, **Next** and **Later**, and grouped by domain within each.
The theme is about sequence, not size: *Now* is what is blocking or exposed today,
*Next* is committed work with a known shape, *Later* is real but not yet scheduled.

A record of what has shipped, and what is deliberately excluded, is at the end.

---

# Now

## Release

### Cut a release carrying the security fixes

**Why this is first.** PRs #71 and #73 fixed a critical remote-code-execution path
and twelve further high-severity findings, and both PRs describe the underlying
vulnerabilities in the open — that was a deliberate transparency decision for a
project with a small user base. The consequence is that **v1.1.0 is the newest
tagged release, it is vulnerable, and the exploit is public**. The window closes
when a fixed release exists, so nothing else should go ahead of this.

The release *engineering* is already done: GoReleaser config, amd64/arm64, cosign
keyless signing, syft SBOMs, checksums. What remains is operational.

- Tag and run the release pipeline.
- Write release notes that name the fixed issues plainly, and say which
  configurations were affected — in particular that `--read-only` and the
  `business-user` persona were **not** protected from the PowerShell injection,
  because an operator reading "read-only" would reasonably assume otherwise.
- Call out the breaking changes: `--toolsets system` no longer carries `Registry`
  and `ScheduledTask`; `App mode=launch_executable` is now `LaunchExecutable` and
  needs `shell`; approval webhooks must sign replies; a remote telemetry endpoint
  must be `https`; the status endpoint refuses to bind without a token; `Package`
  installers must be local paths; a `require_plan` plan now needs an approvals
  webhook to apply.

---

# Next

## Security — remainder of the audit

These are the findings from the 2026-08-04 review that PRs #71 and #73 did not
close. Each was recorded in the commit that fixed its neighbours rather than left
implied, so none of this is new information — it is the tail that was deliberately
deferred.

### S1. `Scrape` re-resolves at dial time (DNS rebinding)

`validateScrapeURL` resolves the host and checks the answers against the forbidden
ranges; `fetchReadableText` then hands the *name* to `http.Client`, which resolves
it again. Two lookups mean an attacker-controlled name can answer publicly for the
first and with `127.0.0.1` or an RFC1918 address for the second.

Redirect hops are now re-validated (#71), so this is the remaining half of the same
class. The fix is the one `internal/guardrails/egress/proxy.go` already implements:
resolve once, vet the answers, and dial the **vetted address** with a custom
`DialContext` rather than the name. The proxy is the reference implementation;
`Scrape` should not have a second, weaker one.

*Files:* `pkg/windows/scrape.go`. *Reference:* `egress/proxy.go` `checkTarget`/`dial`.

### S2. Audit session-file truncation is not detected by the chain

`VerifyChainSegment` iterates only the entries it is given, so any prefix of a valid
chain is itself valid — dropping the tail is the most useful edit an attacker can
make, and it verifies clean.

Keying the manifest (#73) closed the forgery half: a record naming a session's head
can no longer be rewritten without the key. What remains is that detection still
depends on a *sealed* manifest record existing, and `VerifyDir` reports an unsealed
session rather than failing it — while a hard kill (the ladder's `Shutdown`) leaves
sessions unsealed as a matter of course.

Options, roughly in order of cost:

- Carry a running entry count into each entry's hash, so a truncated chain is
  internally inconsistent rather than merely short.
- Make a missing seal record a failure when the owning process is demonstrably not
  running, rather than a note.
- Anchor the head off-box on a cadence (the `eventlog` anchor exists but is off by
  default and only anchors when the head advances).

*Files:* `internal/guardrails/audit/{audit,manifest,verify}.go`.

### S3. An existing egress state directory keeps whatever DACL it has

`ensureStateDir` now creates `%ProgramData%\WindowsMCP` with an explicit protected
DACL — Administrators, SYSTEM and the running user — but it deliberately does not
rewrite the DACL of a directory that already exists, on the grounds that an
operator may have set one on purpose.

That leaves the original exposure intact on any machine where a standard user
created the directory first: they own it, they can write `egress-rules.json`, and an
elevated start acts on it. Rule removal is now namespace-constrained (#73), which
blunts the worst of it, but `global_block` and `system_proxy` are still honoured
from a file whose owner is never checked.

The fix is to verify owner and DACL before reading, and refuse the state rather than
act on it — the pattern `checkCredentialsFileACL` already establishes, which #73
extended to an allowlist plus an owner check. Reuse it rather than writing a third
variant.

*Files:* `internal/guardrails/egress/state_windows.go`, `enforcer_windows.go`.
*Reference:* `internal/winmcp/credfileacl_windows.go`.

### S4. The journey recorder samples password state after the keystroke

Redaction now fails closed and ignores injected input (#73), but *when* it decides
is still wrong. The keystroke crosses the hook channel, and the focused element's
`IsPassword` is read afterwards, on the STA thread — so a fast Tab out of a password
field, or a busy STA thread, classifies the character against whatever has focus by
then.

The recorder already does the right thing for the modifier state: shift and caps
are sampled **synchronously on the hook thread** (`journeyhook_windows.go`) for
exactly this reason. The password state needs the same treatment, which means
either a cheap synchronous read on the hook thread or carrying a sequence number so
the classification is matched to the keystroke it belongs to.

*Files:* `internal/desktop/journeyrecord.go`, `journeyhook_windows.go`.

### S5. `pwsh` is resolved by PATH search

`resolvePwsh` scans the merged PATH and accepts `.exe`, `.cmd` and `.bat`. The merged
PATH includes `HKCU\Environment\Path`, which the `Registry` tool can write and which
already contains user-writable directories by default
(`%LOCALAPPDATA%\Microsoft\WindowsApps`).

On a machine without PowerShell 7 the search reaches those directories, so a planted
`pwsh.cmd` would be executed by every shell-backed tool — including `EventLog` and
`Network`, which are annotated read-only. Mitigated in practice by system PATH
entries coming first and by `psEnvOnce` caching the result, but the ordering is
incidental rather than enforced.

Resolve the interpreter from a fixed set of trusted absolute locations
(`%ProgramFiles%\PowerShell\7\pwsh.exe`, `System32\WindowsPowerShell\v1.0`), never
`.cmd` or `.bat`, and ignore HKCU entries when locating it — user PATH is
legitimately needed for the *child's* environment, not for finding the shell.

*Files:* `internal/desktop/winenv.go`.

### S6. No panic recovery on the stdio transport

A handler panic outside the COM `Do`/`safeCall` boundary takes the process down.
This is a deliberate stance, argued in `conformance_host.go`: a panic means unknown
engine state, and driving a desktop from unknown state is worse than stopping.

The stance is defensible; the failure mode is not fully thought through. Today the
process simply dies — no banner, no seal, no recording finalize, no audit entry
saying why. The kill ladder exists to make exactly that sequence orderly.

Proposal: a narrow recover on the receiving path that converts a handler panic into
an `IsError` result **and trips the kill switch**, so the session is contained and
recorded rather than merely ending. That keeps the fail-stop intent while producing
evidence.

*Files:* `internal/winmcp/server.go`, `internal/guardrails/contain/killaction.go`.

### S7. Installed credentials are not reconciled after an abnormal exit

Removal is correctly wired to both the normal-exit defer and the kill executor's
`Finalize`, via one `sync.Once`. But `TerminateProcess`, a host killing the stdio
child, power loss or an OOM leaves the credential in the user's Credential Manager
until logoff. `CRED_PERSIST_SESSION` bounds it; the window is the rest of the
desktop session.

There is no start-time sweep. The egress enforcer solves the identical problem by
persisting what it created and running `Recover()` on **every** start, "because
rules outlive the process that made them" — credentials outlive it identically.
Targets are unique and known from the credentials file, so a sweep at load is
straightforward.

Related, and cheap to fix alongside: `KillProcesses` runs *before* `finalize()` in
the ladder, so a policy whose `proc_names` matches this server terminates it before
its own cleanup.

*Files:* `internal/winmcp/credentials.go`, `internal/guardrails/contain/killaction.go`.
*Reference:* `internal/guardrails/egress/state_windows.go`.

### S8. Protected paths bind one tool, not the surface

`ProtectedPathViolation` is consulted from exactly one place: the `FileSystem`
handler. `PowerShell`, `LaunchExecutable`, `Package` and `ScheduledTask` reach the
same files with no check at all.

This is why the `shell` toolset requires an explicit acknowledgement to be served
alongside credentials, and the README now says so — but the asymmetry is worth
closing rather than documenting forever. Path normalisation also still folds only
the spellings #73 addressed (`\\?\`, `::$DATA`, trailing dots and spaces); 8.3 short
names, hard links and `\\localhost\C$` reach the file under another name, which
needs comparison by file ID (`GetFinalPathNameByHandle`) rather than by string.

Two candidate shapes, worth deciding between rather than drifting:

1. Enforce at the OS layer — an ACL on the guardrail directories that denies the
   session user — which binds every tool including ones not yet written.
2. Keep it in the tool layer but make the check a shared pre-flight every
   file-touching handler must pass, with a test that fails when a new handler
   skips it.

*Files:* `pkg/windows/{dependencies,protectedpath,filesystem}.go`.

### S9. `FileSystem` accepts UNC paths

`resolvePath` returns `\\attacker\share\x` untouched, so a read or write is SMB
egress — outside the proxy and the allowlist — and authenticates to the remote host
with the user's NTLM credentials. The tool now carries `OpenWorldHint` (#71) so a
policy *can* gate it, but nothing refuses it by default.

Decide whether UNC is refused outright, or permitted only when the host matches the
egress allowlist. The second is more useful and more work.

*Files:* `pkg/windows/filesystem.go`.

## Security — process and infrastructure

### S10. The conformance host's test methodology exposes it

The `conformance` build tag genuinely keeps the HTTP listener out of released
binaries, and CI proves it by grepping an untagged `--help`. That part is sound and
should stay.

The exposure is `HANDOFF-vm-testing.md`, which instructs `netsh portproxy` from
`0.0.0.0` to the loopback-bound host. The only remaining control is the SDK's
Host-header check, which is anti-DNS-rebinding, **not** authentication — any client
sets that header, and the repo's own `vmrelay.exe` exists to do so. There is no
token and no TLS, and Origin verification is off by default in go-sdk v1.7.0.

This is a process fix, not a code one: bridge host-loopback to guest-loopback over
PowerShell Direct or an SSH tunnel, never `0.0.0.0`. If the endpoint must be
reachable, add a bearer token and enable Origin verification. The handoff document
also carries live VM credentials and is correctly gitignored — keep it that way and
rotate those credentials.

### S11. Verify the Dependabot auto-merge gate

`auto-merge-dependabot.yml` uses the safe `pull_request` trigger and gates on the
actor, but enables auto-merge for any non-major bump with `contents: write`. That is
safe **only** if branch protection requires the build, test and lint checks. Confirm
the branch-protection configuration; if it does not, either add the required checks
or restrict auto-merge to patch-only.

## Capability

### PowerShell command tiering

An operator-supplied allowlist or denylist of cmdlets the server may run, so `shell`
becomes a graduated capability rather than all-or-nothing. Agreed to follow the
remediation work rather than being folded into it.

Design questions worth settling before implementation:

- Where enforcement lives. Parsing PowerShell to decide what a script *will* do is
  not tractable in general; a realistic design constrains what can be **submitted**
  (an allowlist of cmdlets with an AST check, refusing anything using dynamic
  invocation, `Invoke-Expression`, `&`, or encoded payloads) rather than trying to
  sandbox arbitrary script.
- Whether it composes with `require_plan` and the `hold` disposition, or replaces
  them for shell specifically.
- How it interacts with the tools that build PowerShell internally — `EventLog`,
  `Network`, `Registry`, `ScheduledTask`, `Package` all do, and they must not be
  caught by a tier meant for the `PowerShell` tool.

## Validation

### B. 1.3 — Adversarial prompt harness

A scripted set of agent-side attacks against a throwaway VM, in CI where possible.
The audit sharpens what it should target, since several of these were real:

- chain benign-annotated tools into a destructive outcome (the reason `Type` and
  `Shortcut` are now annotated destructive — `win+r` was arbitrary execution);
- retrieve an installed credential by any route (injection into an unmasked field
  was the one that worked);
- get traffic out around the egress allowlist;
- actuate containment the agent should not reach (the kill sentinel was writable);
- cause the audit chain to skip, gap, or omit an attempted containment action
  (refused calls were not audited at all until #71).

Each of those is now fixed and each has a regression test, so the harness is
validating that the fixes hold end to end rather than looking for them fresh.

### A. Journey recorder — manual desktop validation

The recorder is merged, but its live capture path — the low-level input hooks and
the UIA hit-test — cannot run in CI and self-skips there. The emitter, the redaction
guarantee and the key translation are unit-tested; the hook and UIA path needs a
manual smoke test on a real desktop:

- run `windows-mcp-server journey record --out j.json`, click several *named*
  controls, type into a normal field **and** a password field, press **F9** to stop;
- confirm the file targets clicks by element name, coalesces the typed text, and
  shows a **redacted** step where the password was typed.

Now also worth confirming, since #73 changed both: that redaction fails **closed**
where UIA cannot report the focused element, and that keystrokes injected by a
concurrent agent session are **not** captured.

---

# Later

## Security

### C. 1.4 — External penetration test

A conventional network-attacker brief tests almost nothing here: there is no HTTP
listener in the shipped binary and the transport is stdio. Scope two passes:

1. **Red-teamer in the agent's seat**, driven by injected content, attempting the
   objectives in B.
2. **Local admin**, attempting to spoof device signals, rewrite the audit chain and
   disable the transparency layer — the question being what evidence survives, not
   whether it can be done. The chain is now keyed by default and the manifest is
   MAC'd, so the honest question is where the key lives and what an off-box anchor
   would add.

`docs/security-architecture.md` is the input to the brief. Sequence it after B, so
consultancy rates are not paid for what a fuzzer or the harness would have found.

## Distribution

### D. Registry and package submissions

The remaining half of the release work, once a fixed release is out (see **Now**):

- submit the winget manifest (the stanza is drafted with `skip_upload`);
- list in the MCP registry.

---

## Delivered

### Security remediation (PRs #71, #73 — 2026-08)

A full defensive review of `main` produced findings across critical, high, medium
and low severity. Every critical and high finding is fixed, along with most of the
medium and low set — each with the regression test that would have caught it. The
remainder is **S1–S11** above.

Highlights, because they change what the documented guarantees actually mean:

- **Arbitrary code execution from read-only tools.** `psQuote` escaped only the
  ASCII apostrophe, but PowerShell's lexer also closes a literal on `U+2018`,
  `U+2019`, `U+201A` and `U+201B`. Reachable from `EventLog` and `Network`, both
  annotated read-only, so `--read-only` and the `business-user` persona had full
  code execution. Quoting is replaced by data binding (`internal/psdata`).
- **Refused calls were never audited.** The receiving middleware was installed one
  call at a time, and each call wraps the previous — so the policy engine ended up
  *outside* the audit layer and every denial, kill, hold-refusal and plan-refusal
  produced no `tool.call` entry at all.
- **The never-read credential guarantee did not hold.** `inject` accepted any
  target, so the agent could type the secret into Notepad and read it back. It now
  requires a UIA-confirmed masked field, failing closed, with a per-credential
  opt-out.
- **The agent could actuate containment.** The kill sentinel was authenticated by
  its own existence, so one file write ran the ladder — the escalation the
  agent-facing `Kill` tool is deliberately denied.
- **The audit chain was forgeable.** Unkeyed by default, and the key leaked to the
  model anyway because every host environment variable was inherited by child
  processes. Both fixed; the chain is keyed by default and the manifest is MAC'd.
- **A local user could escalate through the egress state file.** `%ProgramData%`
  lets a standard user own the directory, and an elevated start acted on its
  contents — deleting arbitrary firewall rules, flipping the machine's default
  outbound action, or writing proxy settings into the admin's registry.
- **Toolset and annotation corrections.** `Registry`/`ScheduledTask` moved to a
  non-default `system-admin` toolset; `launch_executable` became `LaunchExecutable`
  in `shell`; `App`, `Type`, `Shortcut`, `MultiEdit` and `Credentials` gained the
  `DestructiveHint` that policy rules and rate limits match on.

### Prior phases

- **Phase 0 — correctness & security:** file-per-session audit chain with a chained
  manifest and segment verification (0.1); HMAC keying + off-box head anchoring
  (0.2); credentials×shell/filesystem startup refusal with an audited policy
  override (0.3); tool-composition hardening (0.4); the qualified→fixed credentials
  claim (2.5).
- **Phase 1 (code):** fuzzing of `hostmatch` and the policy parser on a scheduled
  workflow (1.1); property tests of the engine invariants (1.2).
- **Phase 2 (code/docs):** README lead rewrite + actor/capability/control/residual
  threat model (2.1/2.2); approver and use-case docs (2.3); GoReleaser config with
  signed archives, SBOM and checksums (2.4 — code).
- **Phase 3 — new capability:** `policy test` verb (3.1); plan-and-apply (3.2);
  signed evidence bundles + auto-seal (3.3); OTLP export (3.4); journeys-as-code —
  runner and recorder (3.5); dual control via the `hold` disposition and approval
  webhook (3.6).
- **Phase 4 — tools:** `EventLog`, `Network`, `ScheduledTask`, `Package`.
- **Lexicon:** two ratified consistency sweeps — the `approve`→`hold` disposition
  and past-tense audit-event names — plus the documented env-var secret rule.

---

## Deliberately not on this list

Stated so they are not re-litigated:

- **Vision-model fallback.** The accessibility-tree-only design is a differentiator
  and a data-residency argument: desktop pixels containing customer data never leave
  the machine. Do not dilute it.
- **Secure desktop / UAC / elevated-app automation.** Platform boundaries, correctly
  documented as non-goals. The honesty about this builds more trust than the feature
  would.
- **An HTTP transport in the shipped binary.** The absence of a listener is a
  security property worth keeping; the conformance host covers the testing need
  behind a build tag. See **S10** for the operational care this still requires.
- **Sandboxing the tools.** `PowerShell`, `Registry`, `FileSystem`, `Process` and
  `App` have full user-context access by design, which `SECURITY.md` states as
  scope. The controls bound *which* surface is served and record what was done;
  they do not pretend to contain a tool that is doing its job.
