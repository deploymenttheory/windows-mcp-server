# windows-mcp-server — Roadmap (what's left)

**Repo:** `github.com/deploymenttheory/windows-mcp-server`

**Purpose of this document:** what remains below is the work that is
*not* code — external validation, a paid engagement, and release/submission
operations — plus a short record of what shipped and what was deliberately left
out.

---

## Delivered

Every implementation item from the original review is merged to `main`:

- **Phase 0 — correctness & security:** file-per-session audit chain with a chained
  manifest and segment verification (0.1); optional HMAC keying + off-box head
  anchoring (0.2); credentials×shell/filesystem startup refusal with an audited
  policy override (0.3); tool-composition hardening — persona bypass refusal,
  pinned always-served tools, FileSystem protected paths (0.4); the qualified→fixed
  credentials claim (2.5).
- **Phase 1 (code parts):** fuzzing of `hostmatch` and the policy parser on a
  scheduled workflow (1.1); property tests of the engine invariants (1.2).
- **Phase 2 (code/docs):** README lead rewrite + actor/capability/control/residual
  threat model (2.1/2.2); approver + use-case docs (2.3); GoReleaser config with
  signed archives, SBOM and checksums (2.4 — code).
- **Phase 3 — new capability:** `policy test` verb (3.1); plan-and-apply — plan
  model + whole-plan evaluation, `Plan`/`Apply` tools, `require_plan` preventive
  gate (3.2); signed evidence bundles + auto-seal (3.3); OTLP export (3.4);
  journeys-as-code — runner **and** recorder (3.5); dual control via the `hold`
  disposition + approval webhook (3.6).
- **Phase 4 — tools:** `EventLog`, `Network`, `ScheduledTask`, `Package`.
- **Lexicon:** two ratified consistency sweeps — the `approve`→`hold` disposition
  and the past-tense audit-event names, plus the documented env-var secret rule.

---

## Outstanding

### A. Journey recorder — manual desktop validation

The recorder (3.5b) is merged, but its live capture path — the low-level input
hooks and the UIA hit-test — cannot run in CI (no interactive desktop) and
self-skips there. The emitter, the redaction guarantee and the key translation are
unit-tested; the hook/UIA path needs a **manual smoke test on a real desktop**:

- run `windows-mcp-server journey record --out j.json`, click several *named*
  controls, type into a normal field **and** a password field, press **F9** to stop;
- confirm the emitted file targets clicks by element name, coalesces the typed text,
  and shows a **redacted** (empty-text) step where the password was typed.

### B. 1.3 — Adversarial prompt harness

A scripted set of agent-side attacks run against a throwaway VM, in CI where
possible. Targets: chain benign-annotated tools into a destructive outcome;
retrieve an installed credential by any route; get traffic out around the egress
allowlist; prevent the kill switch actuating or the recording finalising; cause the
audit chain to skip, gap, or omit an attempted containment action. Excluded from
the implementation pass because it needs VM/CI infrastructure rather than server
code; clarifies what a paid engagement (C) should and should not look for.

### C. 1.4 — External penetration test (scoping note)

A conventional network-attacker brief tests almost nothing here: there is no HTTP
listener in the shipped binary and the transport is stdio. Scope two passes:

1. **Red-teamer in the agent's seat**, driven by injected content, attempting the
   objectives in B.
2. **Local admin**, attempting to spoof device signals, rewrite the audit chain, and
   disable the transparency layer — the question being what evidence survives, not
   whether it can be done.

The delivered threat-model table (`docs/security-architecture.md`) is the input to
this brief. A paid engagement; sequence it after B so consultancy rates are not paid
for bugs a fuzzer or the harness would have caught.

### D. 2.4 — Release & registry operations

The release *engineering* is done (GoReleaser config, amd64/arm64, cosign keyless
signing, syft SBOMs, checksums; a winget stanza is drafted with `skip_upload`).
What remains is operational / account work, not code:

- publish the GitHub release from the tag (run the release pipeline);
- submit the winget manifest;
- list in the MCP registry.

---

## Deliberately not on this list

Stated so they are not re-litigated:

- **Vision-model fallback.** The accessibility-tree-only design is a differentiator
  and a data-residency argument: desktop pixels containing customer data never leave
  the machine. Do not dilute it.
- **Secure desktop / UAC / elevated-app automation.** Platform boundaries, correctly
  documented as non-goals. The honesty about this builds more trust than a feature
  would.
- **An HTTP transport in the shipped binary.** The absence of a listener is a
  security property worth keeping; the conformance host covers the testing need
  behind a build tag.
