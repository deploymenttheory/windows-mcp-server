# Use case: a first-line support queue that triages itself

**The job:** a queue of "my machine is doing X" tickets, most of which are the same
handful of checks and fixes — is the service running, what does the event log say,
is the VPN adapter up, restart the thing. First-line time goes on gathering state
before anyone can act.

**Why this helps:** the agent can gather that state and perform the routine fixes
the way a technician would, through the real desktop — and every action is gated
on device posture and recorded, so "the agent restarted a service on a managed
laptop" is a policy decision and an audit entry, not an unlogged side effect.

This is the `first-line-support` persona: **diagnose before acting**.

## Start it

```powershell
windows-mcp-server.exe stdio --persona first-line-support
```

It serves `screen`, `interaction`, `apps`, `system`, `shell` and `diagnostics` —
so the agent can read system state (`SystemInfo`, `Process`, `Service`), act
through the UI, and drop to PowerShell for the checks a tool does not cover — with
the workflow guidance to look before it leaps.

## Gate it on posture — the point of the security model

First-line support runs on real user machines, so this is exactly where you want
the policy engine. A starting shape:

```jsonc
{
  "mode": "enforce",
  "rules": [
    { "name": "managed-device", "match": { "toolset": "*" },        "require": ["mdm-enrolled", "run-context"], "on_fail": "deny" },
    { "name": "shell-needs-cg",  "match": { "toolset": "shell" },    "require": ["credential-guard"],            "on_fail": "deny" }
  ]
}
```

Now the agent triages freely on a healthy managed device, and refuses PowerShell
on one whose posture has slipped — with the refusal recorded and re-evaluated next
time, so a device that recovers restores service on its own. Prove the rules with
`policy test` fixtures before rollout; see [Policy configuration](policy-config.md).

## Signing in without handing over secrets

If a fix needs the agent to sign in somewhere, `--credentials-file` installs the
secret into the Windows Credential Manager and the `Credentials` tool **injects**
it as keystrokes — the model never receives the plaintext.

**One caveat that will stop startup, by design.** `first-line-support` carries the
`shell` toolset, and PowerShell can read a stored credential back out of the
Credential Manager — which would defeat the never-read guarantee. So combining
`--credentials-file` with this persona **refuses to start** unless the policy
acknowledges the exposure:

```jsonc
"credentials": { "acknowledge_toolset_exposure": ["shell"] }
```

That makes the residual risk a deliberate, audited choice. If you do not need the
agent to sign in, do not supply a credentials file and the question never arises.
See [Credentials](credentials.md).

## What you get on the record

- **The audit chain** — every check and fix, with argument digests, verifiable
  after the fact with `windows-mcp-server audit verify`.
- **`SystemInfo`** as a resource (`windows://system/info`) for a one-shot inventory.
- Optional **session recording** for the tickets where a picture settles it.

## Related

- [Toolsets and personas](toolsets-and-personas.md) — trimming or extending the persona.
- [Policy configuration](policy-config.md) — the rules that gate it.
- [Deciding to deploy this](deployment-decision.md) — for whoever signs off on it.
