# Documentation

Three ways in, depending on who you are:

- **You want to try it** → [Getting started](getting-started.md).
- **You have to approve it** on a fleet → [Deciding to deploy this](deployment-decision.md)
  — threat model, non-goals, posture tiers, residual risk.
- **You have a job to do** → a UI regression suite that isn't flaky
  ([use case](use-case-ui-regression.md)), or a first-line support queue that
  triages itself ([use case](use-case-first-line-support.md)).

The [root README](../README.md) is the feature overview; the rest is organised by
what you are trying to do.

## Setup and configuration

| Guide | For |
|---|---|
| [Getting started](getting-started.md) | Build, first run, connecting an MCP client, and the two things to do before pointing it at anything real |
| [Toolsets and personas](toolsets-and-personas.md) | What every tool does, how to select a subset, what a persona is and how far it can be customised |
| [Policy configuration](policy-config.md) | The device-policy document: full schema reference, signals, rules, verdicts, rate limits, kill switch |
| [Egress setup](egress.md) | Restricting which domains the device may reach — proxy, scoped firewall rules, machine-wide default-deny, and how to verify each tier |
| [Credentials](credentials.md) | Letting the agent sign in without ever seeing a secret |
| [Plan and apply](plan-and-apply.md) | Proposing a whole sequence of tool calls, adjudicated up front and executed verbatim — the opt-in `planning` toolset |
| [Session recording](recording.md) | Recording sessions for audit and playback; codecs, ffmpeg, markers, retention |
| [Remote signals](remote-signals.md) | Microsoft Graph compliance and an external may-run endpoint — the signals a local admin cannot spoof |
| [Monitoring](monitoring.md) | The loopback status endpoint and the hash-chained audit log |
| [Evidence bundles](evidence-bundles.md) | Sealing a session's audit chain, verdicts and recording into one signed, self-verifying archive |
| [Deployment](deployment.md) | Putting this on a managed machine: layout, ACLs, running at logon, pairing with WDAC |
| [Deciding to deploy this](deployment-decision.md) | For the approver: what you are allowing, the threat model, non-goals, choosing a posture, and the residual risk to sign off |
| [VM isolation](vm-isolation.md) | **Design/research note.** Why a disposable VM is stronger containment than in-process controls, comparing Windows Sandbox, Hyper-V VMMS and the HCS API |

## By use case

| Walk-through | For |
|---|---|
| [A UI regression suite that isn't flaky](use-case-ui-regression.md) | Driving an app's GUI by control label instead of coordinates, with evidence on every run — the `qa-test-engineer` persona |
| [A first-line support queue that triages itself](use-case-first-line-support.md) | Gathering state and doing routine fixes, gated on device posture and recorded — the `first-line-support` persona |

## Design and reference

| Document | Contents |
|---|---|
| [Security architecture](security-architecture.md) | How the policy engine, audit chain, rug-pull detection, kill switch, credentials and egress fit together — with diagrams, the containment ladder, the privilege-degrade model, a threat-model mapping, the trust model and a component/file map |
| [MCP compliance](mcp-compliance.md) | Per-scenario results from the official conformance suite at protocol revision `2026-07-28`. **Generated** by `.github/workflows/mcp-spec-compliance.yml`; do not edit by hand |

## For contributors

- [CONTRIBUTING.md](../CONTRIBUTING.md) — build, test, lint and PR conventions.
- [CLAUDE.md](../CLAUDE.md) — the load-bearing internal conventions: the COM STA
  thread rule, the tool-authoring checklist, parameter-coercion and result
  semantics, the egress invariants, and the build-tag split. Useful to humans and
  AI agents alike.
- [SECURITY.md](../SECURITY.md) — how to report a vulnerability, and what falls
  outside scope given the project's deliberate no-sandboxing design.
- `../policy/examples/` — six starting-point policy documents, validated by the
  test suite.
