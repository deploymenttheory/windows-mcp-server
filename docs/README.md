# Documentation

Design and reference documentation for `windows-mcp-server`. Start with the
[root README](../README.md) for installation, MCP client setup, the tool and
persona inventory, and the full flag reference.

## Contents

| Document | What it covers |
|---|---|
| [security-architecture.md](security-architecture.md) | The four-layer security design in depth, with Mermaid diagrams: pre-flight admission, in-flight polling, inline tool-call policy, and transparency (hash-chained audit, heartbeat, rug-pull detection, security banner). Includes the kill-switch arming gate and tiered action ladder, the privilege degrade model, a threat-model mapping, the trust model, and a component/file map. |
| [vm-isolation.md](vm-isolation.md) | **Design/research note, not a shipped feature.** Why a disposable VM is stronger containment than in-process controls, comparing Windows Sandbox, Hyper-V VMMS, and the Host Compute System (HCS) API — including a prototyped HCS flow that is invisible to Hyper-V Manager and `Get-VM`. |
| [markdown-syntax-guide.md](markdown-syntax-guide.md) | Markdown reference for authoring these docs. |

## For contributors

- [CONTRIBUTING.md](../CONTRIBUTING.md) — build, test, lint, and PR conventions.
- [CLAUDE.md](../CLAUDE.md) — the load-bearing internal conventions: the COM STA
  thread rule, the tool-authoring checklist, parameter-coercion and result
  semantics, and the build-tag split. Useful to humans and AI agents alike.
- [SECURITY.md](../SECURITY.md) — how to report a vulnerability, and what falls
  outside scope given the project's deliberate no-sandboxing design.
