# Documentation

Start with [Getting started](getting-started.md). The rest is organised by what
you are trying to do. The [root README](../README.md) is the feature overview.

## Setup and configuration

| Guide | For |
|---|---|
| [Getting started](getting-started.md) | Build, first run, connecting an MCP client, and the two things to do before pointing it at anything real |
| [Toolsets and personas](toolsets-and-personas.md) | What every tool does, how to select a subset, what a persona is and how far it can be customised |
| [Policy configuration](policy-config.md) | The device-policy document: full schema reference, signals, rules, verdicts, rate limits, kill switch |
| [Egress setup](egress.md) | Restricting which domains the device may reach — proxy, scoped firewall rules, machine-wide default-deny, and how to verify each tier |
| [Credentials](credentials.md) | Letting the agent sign in without ever seeing a secret |
| [Session recording](recording.md) | Recording sessions for audit and playback; codecs, ffmpeg, markers, retention |
| [Remote signals](remote-signals.md) | Microsoft Graph compliance and an external may-run endpoint — the signals a local admin cannot spoof |
| [Monitoring](monitoring.md) | The loopback status endpoint and the hash-chained audit log |
| [Deployment](deployment.md) | Putting this on a managed machine: layout, ACLs, running at logon, pairing with WDAC |
| [VM isolation](vm-isolation.md) | **Design/research note.** Why a disposable VM is stronger containment than in-process controls, comparing Windows Sandbox, Hyper-V VMMS and the HCS API |

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
- `../policy/examples/` — five starting-point policy documents, validated by the
  test suite.
