# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities privately through GitHub's private
vulnerability reporting: open the
[Security tab](https://github.com/deploymenttheory/windows-mcp-server/security/advisories)
of this repository and choose **Report a vulnerability**.

Do not open a public issue for a security problem.

Please include, as far as you can:

- affected version or commit, and your Windows version and architecture
- the flags/persona the server was running with
- steps to reproduce, and what an attacker gains

We aim to acknowledge a report within 5 working days and to keep you updated as
we investigate. Please give us a reasonable opportunity to ship a fix before any
public disclosure.

## Supported versions

Only the latest tagged release and the current `main` branch are supported.
Please reproduce against latest `main` before reporting: fixes land there first,
and several releases carry security fixes made after them.

## Scope — what is *not* a vulnerability

This server exists to drive the Windows desktop on behalf of an AI agent, and
several of its tools (`PowerShell`, `Registry`, `FileSystem`, `Process`, `App`)
intentionally have **full user-context system access with no sandboxing**. This
is documented in the [README](README.md) and is the design, not a flaw.
Reports amounting to "the PowerShell tool can run PowerShell" are out of scope.

Likewise, the local pre-flight and posture checks (`dsregcmd`, registry, WMI) are
documented as **auditable defense-in-depth, not a hard boundary** — a local
administrator can spoof those signals. See
[docs/security-architecture.md](docs/security-architecture.md#trust-model). The
containment layers raise the cost of, and record, in-session compromise; they do
not replace WDAC/AppLocker, Conditional Access, or code signing.

In scope, and genuinely interesting to us:

- a way for the **agent** to bypass a control it should not be able to reach:
  the receiving middleware, the policy engine, the rate limits, the audit chain,
  the kill switch, the egress proxy, or the rug-pull detector
- a way to forge or silently break the hash-chained audit log
- privilege escalation beyond the context the server was launched in
- a control that the flags and docs claim is off but which is actually active, or
  vice versa
- any path by which a credential supplied via `--credentials-file` becomes
  readable to the agent — a tool result, an error message, a log line, or the
  audit chain that discloses plaintext. The design guarantees secrets can be
  *used* but never *read*; a break in that is squarely in scope. Note that
  plaintext living in this process's memory is documented residual risk, not a
  vulnerability
