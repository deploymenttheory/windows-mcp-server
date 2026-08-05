<#
.SYNOPSIS
  Prepare a weave-installed Windows guest to host the acceptance suite, then stop.

.DESCRIPTION
  Run this once inside a guest created by `weave create --from-windows`, then
  take the golden snapshot.

  It is deliberately small, because weave's unattended install has already done
  the hard parts at first logon:

    - the local admin account (weave/weave) and permanent autologon — its answer
      file sets AutoAdminLogon and *deletes* AutoLogonCount, so the console
      session survives every reboot and every snapshot revert. That is the thing
      that made the previous Hyper-V lab expensive, and weave already solved it.
    - OpenSSH server, installed and started, with a converge-across-reboots
      retry because the capability pull takes ~9 minutes.
    - the static NIC configuration the HCS backend needs (it has no DHCP).

  So do not pass --unattend-file when creating the guest: it replaces weave's
  answer file, and with it the SSH enablement and the setup-complete signal that
  `weave run` waits on.

  This script installs no Go toolchain: the binary under test is built on the
  host and pushed in per run, so the guest never has to match the host toolchain
  and a run cannot accidentally test a stale in-guest build.

  Snapshot AFTER running this. Reverting removes everything below along with
  everything else, which is the isolation the suite relies on — and the reason a
  snapshot taken before provisioning is useless.
#>
[CmdletBinding()]
param(
  [string]$WorkDir = 'C:\acc',
  # weave's answer file creates and auto-logs-on this account.
  [string]$InteractiveUser = 'weave'
)

$ErrorActionPreference = 'Stop'

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

Step "work directory at $WorkDir"
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

Step 'the interactive runner'
# The suite looks for this and skips the UI scenarios when it is missing, rather
# than running them in session 0 and failing for the wrong reason.
$src = Join-Path $PSScriptRoot 'run-interactive.ps1'
if (Test-Path -LiteralPath $src) {
  Copy-Item -LiteralPath $src -Destination (Join-Path $WorkDir 'run-interactive.ps1') -Force
} else {
  Write-Warning "run-interactive.ps1 not found next to this script; copy it to $WorkDir by hand"
}
[Environment]::SetEnvironmentVariable('ACC_INTERACTIVE_USER', $InteractiveUser, 'Machine')

Step 'turn off what makes a desktop unpredictable'
# Each of these is a source of a UI test failing for a reason that has nothing to
# do with the code under test.
$explorer = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
New-ItemProperty -Path $explorer -Name 'HideFileExt' -Value 0 -PropertyType DWord -Force | Out-Null
# No screen saver and no sleep: a locked desktop cannot be automated at all, and
# the secure desktop is a documented non-goal rather than something to work around.
Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'ScreenSaveActive' -Value '0'
powercfg /change monitor-timeout-ac 0
powercfg /change standby-timeout-ac 0
# Windows Update deciding to reboot mid-suite is the classic overnight failure.
$au = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
New-Item -Path $au -Force | Out-Null
New-ItemProperty -Path $au -Name 'NoAutoUpdate' -Value 1 -PropertyType DWord -Force | Out-Null

Step 'a desktop worth automating'
if (-not (Get-Command notepad.exe -ErrorAction SilentlyContinue)) {
  Write-Warning 'notepad.exe not found; the example journey will not run on this image'
}

Step 'verify'
$problems = @()
$sshd = Get-Service sshd -ErrorAction SilentlyContinue
if (-not $sshd) {
  $problems += "sshd is not installed. weave's first-logon setup installs it and " +
               "logs to C:\Windows\Temp\weave-setup.log — read that before doing it by hand."
} elseif ($sshd.Status -ne 'Running') {
  $problems += "sshd is $($sshd.Status); see C:\Windows\Temp\weave-setup.log"
}
if (-not (Test-Path (Join-Path $WorkDir 'run-interactive.ps1'))) {
  $problems += 'the interactive runner is missing'
}
# The console session weave's autologon should already have established. If this
# fails, the guest was created with a --unattend-file that replaced weave's.
if (-not ((query user 2>$null) -match $InteractiveUser)) {
  $problems += "no console session for '$InteractiveUser'. weave's answer file makes " +
               "autologon permanent, so this usually means the guest was created with " +
               "--unattend-file, which replaces it."
}

if ($problems) {
  Write-Host ''
  Write-Host 'NOT READY:' -ForegroundColor Red
  $problems | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
  exit 1
}

Write-Host ''
Write-Host 'Ready. Take the golden snapshot now:' -ForegroundColor Green
Write-Host '  weave snapshot create <vm> golden -d "windows-mcp acceptance baseline"'
