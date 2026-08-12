# Acceptance testing on a disposable guest

The acceptance suite drives the **shipped binary** against a disposable Windows
guest. It covers three things a CI runner cannot:

- **the desktop engine**, which needs an interactive session with a window
  station — the CI suites skip with *"cannot start desktop engine in this
  environment"* and *"no displays reported (headless)"*;
- **the guardrails that need elevation or change machine state** — firewall
  rules, default-deny outbound, the system proxy;
- **the audit chain when a process is killed** rather than shut down, which is
  the state that leaves a session unsealed.

It is gated, operator-run, and never part of CI.

```powershell
$env:WINDOWS_MCP_ACC = "1"
$env:WINDOWS_MCP_ACC_WEAVE = "D:\weave\weave.exe"   # or have weave on PATH
$env:WINDOWS_MCP_ACC_GUEST = "acc"                  # the VM `weave list` names
go test ./internal/acceptance/ -count=1 -v -timeout 60m
```

With the gate unset every test skips. The scenarios revert snapshots and kill
processes, so they must not run unattended.

## What it needs

- A Windows host with the virtualization platform enabled and membership of
  **Hyper-V Administrators** (no elevation).
- [`weave`](https://github.com/deploymenttheory/guestweave-windows) on `PATH`, or
  `WINDOWS_MCP_ACC_WEAVE` pointing at `weave.exe`. The dependency is the CLI, not
  the Go module — `weave` is pre-alpha and its internals are not importable, and
  it is normally run from a build tree rather than installed.
- A guest built once from the recipe below, with a `golden` snapshot.

The suite checks all three before it stops, reverts or builds anything, so a
missing binary, an unknown guest or an absent snapshot fails in seconds with the
names available rather than partway through a boot.

You do **not** need to source Windows media. `--from-windows pro-25h2` is a media
spec, and weave downloads and caches Microsoft's retail media itself.

## Building the golden image, once

```powershell
# 1. Install Windows, unattended. weave fetches the media and runs the install.
weave create acc --from-windows pro-25h2
weave run acc

# 2. Provision it: the interactive runner and a predictable desktop.
#    Copy acceptance/guest/ into the guest and run provision.ps1 there.

# 3. Snapshot AFTER provisioning.
weave snapshot create acc golden -d "windows-mcp acceptance baseline"
```

**Do not pass `--unattend-file`.** weave generates its own answer file, which
provides three things the suite depends on:

- **Permanent autologon** for the `weave` account: it sets `AutoAdminLogon` and
  deletes `AutoLogonCount`, so the console session is present after every boot
  and every snapshot revert. Without it there is no interactive session and no
  UIA. It cannot be added afterwards — writing `DefaultPassword` into Winlogon on
  a live machine is a credential write and is refused.
- **OpenSSH server**, installed and started at first logon, retried across
  reboots because the capability pull takes about nine minutes.
- **The static NIC configuration** the HCS backend needs, as it has no DHCP.

A supplied answer file replaces all of it, including the setup-complete signal
`weave run` waits on.

**Snapshot after provisioning, not before.** A revert removes the whole
customisation, which is the isolation the suite relies on.

## What a run does

1. Builds the binary under test on the host, into `t.TempDir()`.
2. `weave snapshot revert acc golden`, boots, waits for SSH.
3. Pushes the binary into `C:\acc`.
4. Runs the scenarios.
5. Stops the guest, unless `WINDOWS_MCP_ACC_KEEP=1`.

Isolation is by revert rather than by cleanup: the scenarios kill processes and
tamper with files, so a test that fails partway through cannot be relied on to
undo its own damage.

### Two worlds inside the guest

| Runs where | Reached by | Used for |
|---|---|---|
| Session 0 | `weave ssh` | every CLI verb: `audit verify`, `evidence …`, tampering, process control |
| Console session | `C:\acc\run-interactive.ps1` | anything touching UIA — a journey run |

A command sent over SSH lands in session 0, which has no window station, so UIA
calls there fail or return nothing. The interactive runner hands work to the
`weave` user's console session through a scheduled task with an `Interactive`
logon type. Scenarios needing it **skip** when it is absent, so a missing runner
does not present as a UIA failure.

## Knobs

| Variable | Effect |
|---|---|
| `WINDOWS_MCP_ACC=1` | Required. Without it everything skips. |
| `WINDOWS_MCP_ACC_WEAVE` | Full path to `weave.exe`, when it is not on `PATH`. |
| `WINDOWS_MCP_ACC_GUEST` | The weave VM to drive (default `acc`). |
| `WINDOWS_MCP_ACC_SNAPSHOT` | The snapshot to revert to (default `golden`). |
| `WINDOWS_MCP_ACC_KEEP=1` | Leave the guest running after the suite, to inspect a failure with `weave console`. |
| `WINDOWS_MCP_ACC_RECORDER=1` | Enable the manual recorder check (see below). |
| `WINDOWS_MCP_ACC_PAIRED=1` | Enable the paired harness+server slice (see below). It builds a second binary and drives two processes; a routine run should not. |

## What slice 1 covers

The audit chain and the evidence bundle:

- a clean session **seals**, and `--strict` passes;
- a **sealed** session's chain catches a removed tail, because the manifest holds
  a head the session file cannot rewrite;
- an **unsealed** session is reported (`UNSEALED`, a warning, `--strict` fails)
  but not detected: with no seal there is no recorded head to compare against, and
  any prefix of a valid chain is itself valid. Asserted as it stands; detection is
  open as **S12**, and that test is what changes when it lands;
- a keyed chain carries its MACs and verifies against the key;
- a bundle round-trips, and fails on a **tampered member**, a **dropped member**
  and the **wrong public key**, while still hash-verifying unsigned — integrity
  and provenance are separate promises;
- a journey run's **OTLP/JSON record and screenshots** are sealed into the bundle
  and `journey.finished` reaches `verdicts.json`. *(Needs the console session.)*

## The paired harness+server slice

Gated behind `WINDOWS_MCP_ACC_PAIRED=1` (on top of the base gate). It is the
end-to-end pin for the cross-process behaviour a single-process test cannot
reach: the [agentweave-harness](https://github.com/deploymenttheory/agentweave-harness)
governing the shipped server on the guest as two real processes over the
control channel. The harness binary is built from this repo's pinned module
dependency, so the two binaries under test are the versions this repo actually
ships against, then pushed alongside the server.

- **Refusal on the wire.** An enforcing harness policy denies a `tools/call`;
  the client receives an `IsError` refusal synthesized in the harness, and the
  call never reaches the server (a sentinel in the argument does not
  round-trip).
- **Two chains.** The harness writes its own audit chain of the proxied
  conversation; both it and any server-side host chain `audit verify` green.
- **Never-read across the boundary.** The sentinel argument value appears in no
  recorded frame on either chain — arguments are digested, never recorded raw,
  now provable end to end rather than within one process.
- **Channel-loss teardown.** Killing the harness mid-session closes the
  servant's control pipe, cancels the run context, and the server's LIFO
  teardown runs — asserted by the governed child exiting rather than orphaning.

## The recorder is checked by hand

`internal/desktop/journeyhook_windows.go` drops every keyboard event carrying
`LLKHF_INJECTED`, so **synthetic input cannot drive the recorder**. That filter is
what keeps a recording made while an agent is working from capturing the agent's
credential injection. Driving the recorder from a test would require a switch to
disable it.

The harness therefore prepares the guest and stops:

```powershell
$env:WINDOWS_MCP_ACC = "1"; $env:WINDOWS_MCP_ACC_RECORDER = "1"; $env:WINDOWS_MCP_ACC_KEEP = "1"
go test ./internal/acceptance/ -run TestRecorderManualPrep -v
# follow the printed instructions in `weave console acc`
go test ./internal/acceptance/ -run TestRecorderManualVerify -v
```

The verify step checks that the typed password appears **nowhere** in the recorded
file, then the parts that depend on what the accessibility tree reports: the
automation-id selector ladder, pattern-driven verb inference, and F8 assertion
marking.

## A known rough edge

`weave` exposes no `cp` verb, so the binary is pushed as base64 over `weave ssh`'s
standard input. `guestweave-windows` has the primitive — `internal/ssh` implements
the SFTP upload `weave agent install` uses — so a `weave cp <vm> <local> <remote>`
verb over it would replace this with one call.

## Adding a slice

Candidates, all unsafe on a workstation and safe on a guest that is about to be
reverted: the elevation and machine-state guardrails
(`WINDOWS_MCP_FIREWALL_TEST`, `_GLOBAL_BLOCK_TEST`, `_SYSPROXY_TEST`), the
credentials never-read invariant against a real Credential Manager, and the
adversarial prompt harness.

Add a file per area beside `audit_test.go` and reuse `harness`: the guest
lifecycle, the interactive runner and the transfer mechanism are shared.
