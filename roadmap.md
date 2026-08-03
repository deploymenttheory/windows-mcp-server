# windows-mcp-server — Review Findings and Roadmap

**Repo:** `github.com/deploymenttheory/windows-mcp-server`
**Reviewed at:** v1.0.0 tag, 106 commits, ~29k LoC Go (~8.3k test)
**Purpose of this document:** hand-off brief for a working session. Each item states the problem, the proposed change, and why it matters, so it can be picked up without the original review conversation.

**Current assessment:** 7.5/10 as-is. 9/10 with the security fixes landed. The final point is adoption and independent scrutiny, not code.

**Guiding thesis for prioritisation:** turn agent actions into reviewable, versioned, attestable artefacts rather than ephemeral side effects. Features that advance that thesis rank above features that add surface area.

---

## Phase 0 — Correctness and security fixes

These are the findings that pull the current score down. All three sit in the guardrails stack, which is the project's stated differentiator, so they matter disproportionately.

### 0.1 Audit chain does not resume across restarts (bug)

**Problem.** `audit.NewAuditLog` starts at `seq = 0` with an empty `prevHash`. `NewSink` opens the target with `O_CREATE|O_WRONLY|O_APPEND` and never reads existing content. Two sessions pointed at the same file produce a single JSONL where the second session restarts the sequence, and `VerifyChain` fails at the first entry of session two with a sequence gap.

**Options.**
- Seed `seq` and `prevHash` from the tail of the existing file on open, or
- Move to file-per-session with a manifest that chains session heads together.

File-per-session is cleaner and composes better with evidence bundles (3.3). If that route is taken, the manifest itself needs to chain, or restart-splitting becomes a way to drop history.

**Also fix:** `VerifyChain` currently assumes a chain rooted at seq 0. It needs to verify a segment given an expected starting seq and prev hash.

### 0.2 Audit chain is unkeyed (design)

**Problem.** `hashEntry` is plain SHA-256 over the entry fields plus `prevHash`. Anyone who can write the JSONL can recompute the whole chain end to end and produce a valid-looking log. It is tamper-evident against accident and process crash, not against an adversary — which is consistent with the stated trust model, but the audit package documentation currently implies more than the construction delivers.

**Proposed.**
- HMAC-SHA256 under a key the session does not hold, or an ed25519 signature over the chain head at seal time; **and**
- Periodic off-box anchoring of the head hash — Graph, syslog, an OTLP endpoint, or the Windows event log with an append-only ACL. Anchoring is what actually buys the property; keying alone still leaves the key on the box in most deployments.
- Anchor cadence and destination belong in the policy document, not flags, consistent with the existing design principle.

**Documentation follow-up:** state plainly in `docs/monitoring.md` what the chain does and does not defend against, in the same register as the existing trust-model section, which gets this right.

### 0.3 Credential isolation is composable away (design)

**Problem.** Installed generic credentials live in the calling user's Credential Manager and are readable by the owning user. Any persona carrying the `shell` toolset can `CredRead` them straight back. `first-line-support` carries `shell`. The README claim that no mode returns plaintext is true of the `Credentials` tool and not true of the toolset composition around it.

**Proposed.**
- `--credentials-file` combined with an enabled `shell` (or `filesystem`, which can read a Credential Manager backup) refuses at startup, or warns loudly and audits the fact. Refusing matches the existing precedent where the firewall tiers refuse to start unelevated rather than serve a weaker posture than the document describes.
- Audit the composition decision either way, so the residual risk is recorded when an operator overrides it.

### 0.4 Audit the wider tool-composition surface (investigation)

0.3 was found by reading. There are likely more. Specific things to check:

- Can `--tools` reintroduce a tool that a persona deliberately excluded? If so, the persona guarantee is advisory rather than enforced.
- Can `--exclude-tools` remove `GuardrailStatus` or `Kill`? Both are documented as always served.
- Does `--read-only` filtering derive from the same annotation the policy engine matches on? If the two can disagree, a rule matching `annotation: read-only` may cover a different set than the flag exposes.
- Can `filesystem` read the policy document, the credentials file, or the audit log? Reading the policy is arguably fine; writing the audit log is not.

---

## Phase 1 — Prove it out

### 1.1 Fuzz the pure, adversarial-input surfaces

Both are platform-independent pure functions with attacker-influenced input, so this is near-free in CI:

- `hostmatch.Compile` and `hostmatch.Match` — the allowlist is a security boundary parsed from operator text and matched against attacker-chosen hostnames.
- The policy document parser in `internal/guardrails/policy/policyconfig.go` — 689 lines, the largest file in the repo, and the input is a document an operator may source from elsewhere.

Add `FuzzXxx` functions with a seed corpus; wire `go test -fuzz` into a scheduled workflow rather than every PR.

### 1.2 Property-test the policy engine invariants

The documented invariants are exactly the kind that break silently:

- Requirements are the union across matching rules — adding a rule never drops a requirement.
- Severity is attributed to the most specific matching rule: tool > annotation > named toolset > `"*"`.
- A denied call is re-evaluated next time, so a recovered signal restores service without restart.

Generate random rule sets and device states, assert the invariants hold. This is higher value than more example-based tests.

### 1.3 Adversarial prompt harness

A scripted set of agent-side attacks run against a throwaway VM, in CI where possible. Targets:

- Chain benign-annotated tools into a destructive outcome.
- Retrieve an installed credential by any route.
- Get traffic out around the egress allowlist.
- Prevent the kill switch actuating, or the recording finalising.
- Cause the audit chain to skip, gap, or omit an attempted containment action.

Clear what this finds before commissioning a paid engagement.

### 1.4 Penetration test — scoping note

A conventional brief will aim at the wrong target. There is no HTTP listener in the shipped binary and the transport is stdio, so a network-attacker frame tests almost nothing. Scope two passes:

1. **Red teamer in the agent's seat**, driven by injected content, attempting the objectives in 1.3.
2. **Local admin**, attempting to spoof device signals, rewrite the audit chain, and disable the transparency layer — with the question being what evidence survives rather than whether it can be done.

The threat-model table (2.2) is the natural input to this brief.

---

## Phase 2 — Framing and release

The writing is good; the ordering and the audience assumptions are the problem.

### 2.1 Rewrite the first fifteen lines of the README

- The Python-port lineage currently leads. It reads as a reimplementation. Move it to a credit line further down.
- Lead with the claim nobody else can make: the only MCP server that gates agent actions on live device posture and constrains the agent's network egress.
- The policy engine, egress allowlist and audit chain are currently three rows in a nine-row feature table, formatted identically to `--overlay`. Rows read as equivalent by construction. Lift them into prose above the table.

### 2.2 Add a threat-model section

Actor / capability / control / residual risk, as a table. It currently has to be assembled from `SECURITY.md`, `docs/security-architecture.md` and the README trust-model paragraph. This does triple duty: README credibility, pen test scoping input, and the artefact a second-line reviewer asks for.

### 2.3 Write for three readers, not one

The current documentation serves the engineer who already wants this. Add entry points for:

- **The approver** — threat model, residual risk, non-goals, deployment posture. Largely 2.2 plus a deployment-decision page.
- **The person with a job to be done** — flaky UI regression suite, first-line support queue. They do not know this category exists. Two short use-case pages beat any amount of feature documentation.

### 2.4 Publish a release

v1.0.0 is tagged with no published release. "Clone and build with Go 1.25" is a steep tax on a Windows audience.

- Signed binaries for amd64 and arm64 via GoReleaser. Code signing matters doubly here because the README correctly names it as part of the real boundary.
- winget manifest.
- Listing in the MCP registry.
- SBOM and provenance attestation, since the audience is enterprise.

### 2.5 Correct the credentials claim

Once 0.3 lands, the README statement about plaintext is accurate. Until then it should be qualified. This is a small edit and worth doing immediately rather than waiting on the fix.

---

## Phase 3 — New capability

Sequenced so each item stands on the one before it.

### 3.1 `policy test` — policy documents as testable code

Fixture device states plus asserted verdicts, run in CI, exiting non-zero on mismatch. Sits alongside the existing `policy validate` / `check` / `explain` verbs.

Today an operator cannot verify that a rule change did not drop a requirement until a live session refuses something. Cheapest item in this phase, unblocks confidence in every subsequent change to the engine, and extends the config-as-code argument to the control plane rather than just the automation. Shares fixture infrastructure with 1.2.

### 3.2 Plan and apply

The single highest-value addition.

The agent proposes a sequence of tool calls. The policy engine evaluates the **whole plan** up front and renders a diff of what will change — files touched, registry keys written, processes killed, domains reached, UI state altered. Only then does it execute.

Why it matters:
- Converts "an agent with system access" into "a change with a reviewable plan." That is the entire objection, answered.
- The mental model is instantly legible to anyone who has run `terraform plan`. No new concept to teach.
- It gives the policy engine somewhere far better to stand. Today it adjudicates one call with no knowledge of the sequence, which is precisely how benign steps compose into a destructive outcome — see 0.3 and 0.4.
- Nobody else in the MCP ecosystem has this.

Design questions to settle: how a plan is represented and whether it is serialisable to disk; what happens when the world changes between plan and apply (posture re-check at apply time, at minimum); whether partial application is permitted or a plan is atomic; how a plan interacts with the containment ladder mid-apply.

### 3.3 Evidence bundles

A session emits one self-contained, signed artefact: recording, audit chain, snapshots, policy verdicts, device posture at start and end, plan and apply record if 3.2 has landed, plus a manifest.

This is the natural home for the chain-anchoring work in 0.2, because the bundle is signed at seal time. In a regulated organisation it converts a security objection into a compliance argument, and it is the thing handed to an auditor or an incident review.

### 3.4 OTLP export

Tool calls as spans, policy verdicts and device signals as metrics and events, kill-switch trips as events.

Everything currently terminates in a local JSONL file, which makes fleet-level questions unanswerable: which policies are denying what, where journeys fail, how posture drifts across an estate. Emitting to a collector makes the server a first-class citizen of an observability estate rather than a black box on an endpoint. Also a second, independent path for audit-head anchoring (0.2).

### 3.5 Journeys as code

A declarative journey file — steps, targets, assertions, expected evidence — executed deterministically by the server, versioned in git, reviewed in a PR, run in CI.

This takes `qa-test-engineer` from a persona to a product, and applies the ClickOps-to-GitOps argument to a domain where nobody has made it yet. It is the largest item here and wants the plan model (3.2) underneath it, since a journey is essentially a pre-authored plan.

**Critical companion:** a recorder that watches a human perform the journey once and emits the file. Authoring cost is what kills this category. Without the recorder, adoption will not happen.

### 3.6 Dual control for destructive actions

A fourth `on_fail` disposition — `approve` — that suspends the call, requests out-of-band human authorisation via webhook, and records the request, the decision and the approver identity in the audit chain.

Four-eyes on privileged action is a control every regulated organisation already mandates for humans. Being the first agent runtime that can express it is a strong position. Needs a timeout policy and a defined default on timeout (deny).

---

## Phase 4 — Tools

Most gaps here are incremental. The principle worth applying: **add a tool when it lets the policy engine make a distinction that PowerShell obscures, not merely when it saves the agent a script.** A dedicated tool can be annotated, gated and planned; a shell command cannot.

| Tool | Value | Note |
|---|---|---|
| `EventLog` | High | First-line triage without it is guesswork. Fits `first-line-support` exactly. Query by log, level, provider, time window. |
| `ScheduledTask` | Medium | Duplicates PowerShell functionally; the gain is that it becomes annotatable and policy-gated. |
| `Package` (winget / MSI) | Medium | Same argument. Install is a genuinely destructive action that currently hides inside `PowerShell`. |
| `Network` (adapter, DNS, connectivity) | Medium | Read-only diagnostics for triage; composes well with the egress story. |

---

## Suggested sequencing

| Phase | Items | Rationale |
|---|---|---|
| **Now** | 0.1, 0.2, 0.3, 0.4, 2.5 | Correctness and honesty. Everything else assumes these. |
| **Next** | 1.1, 1.2, 3.1, 2.1, 2.2 | Cheap confidence plus the framing rewrite. `policy test` lands here because it shares fixtures with 1.2. |
| **Then** | 2.3, 2.4, 1.3 | Release engineering and framing land together — positioning multiplies traction, it does not create it, and with no published release better positioning converts more of a very small stream. |
| **After** | 3.2, 3.3, 3.4, 1.4 | Plan-and-apply is the flagship. Pen test once 1.3 findings are cleared, so consultancy rates are not paid for bugs a fuzzer would have caught. |
| **Later** | 3.5, 3.6, Phase 4 | Journeys-as-code is the biggest single build and wants the plan model underneath it. |

---

## Things deliberately not on this list

Worth stating so they are not re-litigated:

- **Vision-model fallback.** The accessibility-tree-only design is a differentiator, not a gap. It is also a data-residency argument: desktop pixels containing customer data never leave the machine. Do not dilute it.
- **Secure desktop / UAC / elevated-app automation.** Platform boundaries, correctly documented as non-goals. The honesty about this builds more trust with a risk function than any feature would.
- **An HTTP transport in the shipped binary.** The absence of a listener is a security property worth keeping, and the conformance host already covers the testing need behind a build tag.