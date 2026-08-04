# Deciding to deploy this

For the person who has to **approve** this on a fleet — a security or risk
function — rather than the person who installs it. [Deployment](deployment.md) is
the *how*; this page is the *whether*, and *how far*.

- [What you are approving](#what-you-are-approving)
- [The threat model, briefly](#the-threat-model-briefly)
- [Non-goals — what it deliberately does not do](#non-goals--what-it-deliberately-does-not-do)
- [Choosing a posture](#choosing-a-posture)
- [What to monitor](#what-to-monitor)
- [Residual risk to sign off](#residual-risk-to-sign-off)

---

## What you are approving

An MCP server that gives an AI agent the same desktop reach a signed-in user has —
UI automation, PowerShell, the registry, files, applications — and wraps every
action in a policy gate, an egress allowlist, and a tamper-evident audit chain.

It runs with **exactly the privileges of the account it runs as** and raises none.
So the question is not "is desktop automation safe" — it is as safe as that
account — but "are the agent's actions **conditional, bounded, and reviewable**
enough for the risk you are carrying". This mcp server exists to make the answer yes.

## The threat model, briefly

The full actor-by-actor model is in the [README](../README.md#threat-model), mapped
to mechanisms in the [security architecture](security-architecture.md#threat-model-mapping).
The one paragraph an approver needs:

The local device signals and the on-box containment are **auditable
defense-in-depth and evidence, not a hard boundary**. A local administrator can
spoof a signal or attack the log; keying and off-box anchoring raise that bar but
do not remove it. Treat this as one layer that **records and raises the cost** of
in-session compromise, and pair it with the OS controls you already own —
**WDAC/AppLocker**, Conditional Access, and **code signing** of the binary. The
value against a privileged adversary is evidence that survives, not prevention.

## Non-goals — what it deliberately does not do

These are design decisions, not gaps, and each is a smaller attack surface:

- **No vision model.** Perception is the Windows accessibility tree only. This is
  also a data-residency property: desktop pixels that may contain customer data
  never leave the machine.
- **No secure-desktop, UAC, or elevated-app automation.** The Windows sign-in
  screen, lock screen and UAC prompts run on a protected desktop that cannot be
  driven. Assume an already-unlocked, signed-in session.
- **No network listener in the shipped binary.** The transport is stdio only, so
  there is nothing on the network to attack. (A loopback HTTP host exists behind a
  build tag for conformance testing and is never compiled into a release.)

See [VM isolation](vm-isolation.md) for the stronger-containment option — running
the whole thing in a disposable VM — when the workload is untrusted.

## Choosing a posture

Adopt in this order. Each step is reversible and observable before you take the
next.

| Posture | What it does | Cost to adopt |
|---|---|---|
| **Audit** (the default) | Engine on, every signal evaluated, every verdict recorded — **nothing refused**. | None. Behaviour is unchanged from no policy, so it cannot break a working deployment. Adopt first and *read the audit log* to learn what your fleet actually does. |
| **Enforce** | Rules refuse or contain. Gate the destructive surface (`shell`, `filesystem`, destructive-annotated tools) on device posture — MDM enrolment, BitLocker, Secure Boot, Credential Guard. | Write rules, then prove them with `policy test` fixtures in CI before rollout. A recovered signal restores service with no restart. |
| **Egress — proxy-only** | A loopback allowlist the agent is asked to use. Advisory. | Declare the domains. No elevation. |
| **Egress — scoped / global** | Firewall rules so named applications, or the whole machine, cannot bypass the proxy. | Requires elevation; refuses to start without it rather than serving a weaker posture than the document says. |
| **Keyed + anchored audit** | HMAC the chain (`WINDOWS_MCP_AUDIT_KEY`) and publish the head off-box. | For when a local admin is in the threat model and the audit trail must resist them. |

The engine reads a policy document, not flags; it is meant to be reviewed and
checked into source control. Start from `policy/examples/` (`audit.json` first).

## What to monitor

From [Monitoring](monitoring.md):

- **The audit chain.** `windows-mcp-server audit verify <dir>` confirms it is
  unbroken; in directory mode it also checks the cross-session manifest.
- **`credentials.exposure.*`** — whether a session ran with credentials beside a
  toolset that can read them back (it refuses by default; the event records an
  acknowledged override).
- **`killswitch.disarmed`** — something the policy *could* have contained happened
  and the policy chose not to. Watch this specifically.
- **`egress.summary`** — the domains refused this session.
- **The status endpoint** — `admit`, `killed`, `heartbeat_age_sec`, and whether
  egress enforcement is the tier you configured or silently `proxy-only`.

## Residual risk to sign off

What the controls do **not** remove, restated as things you are accepting:

- Benign-annotated tool calls can still **compose** into a harmful outcome within
  the served surface. Scope the surface with personas, and use
  [plan-and-apply](plan-and-apply.md) with `require_plan` where the composition
  risk is real — it adjudicates a whole sequence before any step runs.
- The **audit chain is unkeyed unless `audit_destination` is a file or
  directory**; with `stderr`, the shipped default, there is nowhere to keep a key.
  Keyed, the **HMAC key still sits on the box** unless you anchor the head off it.
- **`FileSystem` path protection** matches by cleaned path — not 8.3 short names
  or hard links — and binds the `FileSystem` tool only. It is a guardrail, not a
  sandbox.
- The **`status_token` belongs in `status_token_env`**, not inline: the policy
  document is readable through the `filesystem` toolset, and `POST /revoke`
  behind that credential runs the containment ladder.
- A **local administrator** can defeat any on-box control. The mitigation is the
  OS controls you pair this with, plus the surviving evidence.

When these are acceptable for the account and machine this runs on, deploy per
[Deployment](deployment.md).
