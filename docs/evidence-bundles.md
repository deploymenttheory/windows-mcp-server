# Evidence bundles

A session leaves a trail — a hash-chained audit log, its verdicts, and optionally
a recording. An **evidence bundle** packages that trail into one self-verifying,
optionally signed archive: the artifact you hand to an auditor or an incident
review. *Here is what the session did, and here is the proof it has not been
edited since.*

## What is in a bundle

`session-<stamp>.evidence.zip` contains:

- `audit/session-<stamp>.audit.jsonl` — the session's audit chain.
- `audit/audit-manifest.jsonl` — the cross-session manifest, when the sink is in
  directory mode.
- `verdicts.json` — the decision-shaped entries (policy decisions, plan
  proposals/steps/applies, approvals, containment, startup admission) lifted out
  of the chain for a reviewer to read first.
- `recording/session-<stamp>.*` — the session video and its markers, when a
  recording directory is given.
- `manifest.json` — every member with its SHA-256 and size, plus the session
  stamp, the audit chain head, and whether the bundle is signed.
- `manifest.sig` — a detached ed25519 signature over the manifest, when signed.

## Signing and trust

The signature is **ed25519, not the audit chain's HMAC**, on purpose: the consumer
of a bundle is a third party who must verify it **without holding a secret**. The
public key travels in the manifest for reference, but real trust comes from the
verifier supplying the key it expects, published out of band.

```powershell
# once: mint a signing key. Keep evidence.key secret; publish evidence.pub.
windows-mcp-server evidence keygen --out C:\keys

# seal a session's evidence, signed
$env:WINDOWS_MCP_EVIDENCE_KEY_FILE = "C:\keys\evidence.key"
windows-mcp-server evidence bundle --dir C:\ProgramData\windows-mcp\audit\ --session 20260803-120000 `
  --recording-dir C:\ProgramData\windows-mcp\recordings

# verify — against the key you expect, not just the one in the bundle
windows-mcp-server evidence verify session-20260803-120000.evidence.zip --pubkey (cat C:\keys\evidence.pub)
```

Signing is never required: with no key the bundle is **unsigned but still
hash-verifiable** — every member is checked against the manifest, so content
tampering, a dropped member or an added one are all caught. Verifying against a
key proves *provenance* on top of that. `verify` exits non-zero on any problem.

## Composing with the rest

The bundle correlates with the [session recording](recording.md) by the shared
`session-<stamp>` name, and with [plan-and-apply](plan-and-apply.md): the
`plan.proposed` / `plan.applied` records in the audit chain are what let a reviewer
compare what was **approved** against what **ran**. The chain in the bundle can be
re-checked independently with `audit verify`, and if it was keyed
([monitoring](monitoring.md)), its own HMAC still holds.

## On demand, or automatically

Bundles are sealed either way:

- **On demand** with `evidence bundle`, from any audit directory, at any time.
- **Automatically at session end** when `transparency.evidence_dir` is set. Every
  session then writes `session-<stamp>.evidence.zip` there as it exits — and the
  automatic seal additionally captures what only exists live: the **full approved
  plan documents** (the audit chain records only their digests) under `plans/`,
  and the **closing posture snapshot** as `posture-end.json`.

```jsonc
"transparency": {
  "audit_sink": "C:\\ProgramData\\windows-mcp\\audit\\",   // must be a directory
  "recording_dir": "C:\\ProgramData\\windows-mcp\\recordings",
  "evidence_dir": "C:\\ProgramData\\windows-mcp\\evidence"
}
```

Auto-sealing requires a **directory-mode `audit_sink`** — there is otherwise no
per-session file to bundle — and it never crashes shutdown: a seal failure is
logged and the session still exits cleanly. Point
`WINDOWS_MCP_EVIDENCE_KEY_FILE` at a signing key to sign the automatic bundles too.
