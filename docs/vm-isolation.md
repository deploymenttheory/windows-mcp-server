# Isolating the server in a disposable VM (HCS)

This server's tools have **full, unsandboxed system access** (PowerShell,
Registry, FileSystem, Process, synthetic input). The in-process
[security model](../README.md#security) contains a *session* —
startup admission, the policy engine, audit, kill switch, egress — but the strongest
containment for untrusted workloads is to run the whole server inside a
**disposable virtual machine** whose blast radius is the VM, not the host.

This note covers the isolation options and, in particular, the
**Host Compute System (HCS)** path — programmatic, disposable VMs that are
invisible to Hyper-V Manager — which is the most operator-friendly fit and is
built on the same [`go-bindings-win32`](https://github.com/deploymenttheory/go-bindings-win32)
SDK this server already uses.

## The options

| Approach | Isolation | Disposable | Host-visible? | Notes |
|---|---|---|---|---|
| **Windows Sandbox** | Strong (VM) | Yes (per launch) | No (HCS VM) | Easiest; ephemeral by design, but limited config (no persistent state, GPU/UIA quirks), and it's driven by a `.wsb` file, not an API. |
| **Hyper-V VM (VMMS)** | Strong (VM) | Manual | **Yes** — appears in Hyper-V Manager / `Get-VM`, and anyone on the host can start/stop/checkpoint it | Full control, persistent, but the VM is a shared host object that out-of-band tools can touch. |
| **HCS compute system** | Strong (VM) | Yes (terminate = gone) | **No** — invisible to Hyper-V Manager / `Get-VM` | The mechanism behind WSL2, Docker's utility VM, and Windows Sandbox. Programmatic, disposable, and the launching process is the **sole controller**. |

## Why HCS

HCS (`vmcompute.dll`) creates a *compute system* on the **Microsoft
Hypervisor** — the same Type-1 hypervisor Hyper-V uses, with the same device
model — but **not** through the Hyper-V VMMS management stack. The result runs
alongside Hyper-V yet:

- **Does not appear in Hyper-V Manager or `Get-VM`.** Like the WSL2 utility VM,
  it's a runtime compute system, so no host-side UI or `Stop-VM`/checkpoint can
  reach in and disturb the isolated agent. The launching process owns it.
- **Is disposable.** `HcsCreateComputeSystem` → `HcsStartComputeSystem` →
  `HcsTerminateComputeSystem`; with `ShouldTerminateOnLastHandleClosed`, the VM
  dies with its supervisor. Perfect for a per-session sandbox.
- **Can be network-isolated** via HNS/HCN endpoints (create the VM on an
  isolated network, or none) — complementing the kill switch's firewall isolate.

This pairs naturally with the existing model: the containment layers guard
what happens *inside* a session; an ephemeral HCS VM bounds *where* it can
happen.

## How it works (prototyped)

The mechanism is a flat C API in `vmcompute.dll`, already generated in
`go-bindings-win32` as `bindings/win32/system/hostcomputesystem` (plus
`hostcomputenetwork` for HNS and `hypervisor` for WHP). No new binding work is
needed — HCS is a Win32 DLL API, not WMI.

1. **Document.** The VM is described by a schema-2 JSON *compute-system
   document* (memory, CPU, a VHDX on SCSI, UEFI boot, optional Secure
   Boot/guest-state, network adapter). Build it as Go structs → JSON, mirroring
   `microsoft/hcsshim`'s `schema2`.
2. **Async lifecycle.** `HcsCreateOperation` → call an `Hcs*` function →
   `HcsWaitForOperationResult` (returns a JSON result/error string). VM stop is
   an event: register `HcsSetComputeSystemCallback` and wait for
   `HcsEventSystemExited`.
3. **Access.** `HcsGrantVmAccess` gives the VM worker access to its VHDX;
   `HcsCreateEmptyGuestStateFile` makes the `.vmgs` firmware NVRAM for Secure
   Boot.

A spike confirmed the core claim on a Hyper-V-Admins host: create → start →
terminate all worked (create/start even **unelevated**; only the guest-state
file for Secure Boot needed admin), and the VM was present in `hcsdiag list`
but **absent from `Get-VM`** — proven invisible while running on the Microsoft
Hypervisor.

## Operational notes

- **Elevation.** The control plane (create/start/stop) can run unelevated with
  Hyper-V-Administrators membership; the Secure-Boot guest-state path needs
  admin (Docker runs its HCS calls in a SYSTEM service — the same pattern
  applies for a hardened deployment).
- **Getting the server into the VM.** Provision the VHDX with an OS +
  autologon + this server auto-started at login (the README's
  [journey guidance](../README.md#what-cannot-be-automated-by-design) already
  recommends autologon + a scheduled task), then boot it as an HCS VM per
  session and terminate on completion.
- **Console.** HCS has no vmconnect; a headed view is the supervisor's own —
  framebuffer capture or RDP-over-HvSocket (the Windows Sandbox model). For an
  RPA agent this is usually headless with `transparency.recording_dir` capturing evidence.

## Status

This is a **design/research note**, not a shipped feature: today, isolate the
server by running it in a Hyper-V VM or Windows Sandbox as the README advises.
A `sandbox` mode that auto-provisions a disposable, invisible HCS VM, boots the
server inside it, and tears it down per session is the natural next step — and
the bindings to build it already exist in `go-bindings-win32`.
