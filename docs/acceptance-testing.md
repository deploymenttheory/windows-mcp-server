# Acceptance testing on a disposable guest

Every interesting property of this server is one CI cannot observe. The Windows
runner compiles everything and runs the pure-logic suites, and then skips:
*"cannot start desktop engine in this environment"*, *"no displays reported
(headless)"*, *"set `WINDOWS_MCP_GLOBAL_BLOCK_TEST=1` to run the tests that make
this machine default-deny"*.

The acceptance suite closes that gap by driving the **shipped binary** against a
disposable Windows guest. It is worth the setup: the last time this server was
driven against a real guest rather than reviewed, it confirmed every fix from the
review **and found four things the review had not**.

It is gated, operator-run, and never part of CI.

```powershell
$env:WINDOWS_MCP_ACC = "1"
go test ./internal/acceptance/ -count=1 -v
```

With the gate unset — which is everywhere except an operator's machine — every
test skips. That is deliberate: these tests revert snapshots and hard-kill
processes, so a suite that ran by accident would be worse than no suite.

## What it needs

- A Windows host with the virtualization platform enabled and membership of
  **Hyper-V Administrators** (no elevation).
- [`weave`](https://github.com/deploymenttheory/guestweave-windows) on `PATH`.
  The dependency is the CLI, not the Go module — `weave` is pre-alpha and its
  internals are not importable.
- A guest built once from the recipe below, with a `golden` snapshot.

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

**Do not pass `--unattend-file`.** weave generates its own answer file, and it
already does the three things this suite depends on:

- **Permanent autologon** for the `weave` account. It sets `AutoAdminLogon` and
  *deletes* `AutoLogonCount` rather than merely setting it, so the console
  session survives every reboot and every snapshot revert. This is the thing that
  made the previous Hyper-V lab expensive — autologon could not be armed after
  installation, because writing `DefaultPassword` into Winlogon on a live machine
  is a credential write and is refused, so a human had to log in at the console
  after every revert. weave already solved it.
- **OpenSSH server**, installed and started at first logon, with a
  converge-across-reboots retry because the capability pull takes about nine
  minutes.
- **The static NIC configuration** the HCS backend needs, since it has no DHCP.

Supplying your own answer file replaces all of that — including the
setup-complete signal `weave run` waits on.

**Snapshot after provisioning, never before.** Reverting removes the whole
customisation along with everything else. That is exactly the isolation the suite
relies on — and the reason a snapshot taken too early is useless.

## What a run does

1. Builds the binary under test on the host, into `t.TempDir()`.
2. `weave snapshot revert acc golden`, boots, waits for SSH.
3. Pushes the binary into `C:\acc`.
4. Runs the scenarios.
5. Stops the guest, unless `WINDOWS_MCP_ACC_KEEP=1`.

Reverting rather than cleaning up is the point: the scenarios hard-kill a process
and tamper with files on disk, and a test that failed halfway would otherwise
leave the next one running against wreckage.

### Two worlds inside the guest

| Runs where | Reached by | Used for |
|---|---|---|
| Session 0 | `weave ssh` | every CLI verb: `audit verify`, `evidence …`, tampering, process control |
| Console session | `C:\acc\run-interactive.ps1` | anything touching UIA — a journey run |

A command sent over SSH lands in session 0, which has no desktop: UIA calls fail
or return nothing. The interactive runner hands work to the `weave` user's
console session — the one weave's permanent autologon establishes — through a
scheduled task with an `Interactive` logon type. Scenarios needing it **skip**
when it is absent, rather than running in session 0 and failing for the wrong
reason.

## Knobs

| Variable | Effect |
|---|---|
| `WINDOWS_MCP_ACC=1` | Required. Without it everything skips. |
| `WINDOWS_MCP_ACC_GUEST` | The weave VM to drive (default `acc`). |
| `WINDOWS_MCP_ACC_SNAPSHOT` | The snapshot to revert to (default `golden`). |
| `WINDOWS_MCP_ACC_KEEP=1` | Leave the guest running after the suite, to inspect a failure with `weave console`. |
| `WINDOWS_MCP_ACC_RECORDER=1` | Enable the manual recorder check (see below). |

## What slice 1 covers

The audit chain and the evidence bundle — the claims the threat model rests on:

- a clean session **seals**, and `--strict` passes;
- a **sealed** session's chain catches a removed tail, via the manifest head
  cross-check;
- an **unsealed** session is loud (`UNSEALED`, a warning, `--strict` fails) but
  **not detected** — which is the honest current state, with detection still open
  as **S12**. When S12 lands, that test is what changes;
- a keyed chain carries its MAC and verifies against the key;
- a bundle round-trips, and fails on a **tampered member**, a **dropped member**,
  and the **wrong public key** — while still hash-verifying unsigned, which is
  the integrity-versus-provenance distinction made concrete;
- a journey run's **OTLP/JSON record and screenshots** are sealed into the bundle
  and `journey.finished` reaches `verdicts.json`. *(Needs the console session.)*

## The recorder is checked by hand, on purpose

`internal/desktop/journeyhook_windows.go` drops every keyboard event carrying
`LLKHF_INJECTED`, so **synthetic input cannot drive the recorder**. That filter is
why a recording made while an agent is working does not capture the agent's
credential injection — whose entire design is that the secret is typed and never
written down. Automating past it would mean shipping a switch to turn it off.

So the harness prepares and stops:

```powershell
$env:WINDOWS_MCP_ACC = "1"; $env:WINDOWS_MCP_ACC_RECORDER = "1"; $env:WINDOWS_MCP_ACC_KEEP = "1"
go test ./internal/acceptance/ -run TestRecorderManualPrep -v
# follow the printed instructions in `weave console acc`
go test ./internal/acceptance/ -run TestRecorderManualVerify -v
```

The verify step checks the guarantee that matters most — that the typed password
appears **nowhere** in the recorded file — plus the things that have never run
against a real accessibility tree: the automation-id selector ladder,
pattern-driven verb inference, and F8 assertion marking.

## A known rough edge

`weave` has no `cp` verb, so the binary is pushed as base64 over `weave ssh`'s
standard input. `guestweave-windows` already has the primitive — `internal/ssh`
implements the SFTP upload `weave agent install` uses — so exposing
`weave cp <vm> <local> <remote>` would replace this with one call. Until then, if
the push fails because standard input is not forwarded, that is the fix to make.

## Adding a slice

The elevation and machine-state guardrails (`WINDOWS_MCP_FIREWALL_TEST`,
`_GLOBAL_BLOCK_TEST`, `_SYSPROXY_TEST`), the credentials never-read invariant
against a real Credential Manager, and the adversarial prompt harness are the
natural next ones — all unsafe on a workstation and all safe on a guest that is
about to be reverted. Add a file per area beside `audit_test.go` and reuse the
`harness`; the guest lifecycle, the interactive runner and the transfer mechanism
are already solved.
