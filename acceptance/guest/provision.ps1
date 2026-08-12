<#
.SYNOPSIS
  Prepare a weave-installed Windows guest to host the acceptance suite, then stop.

.DESCRIPTION
  Run this once inside a guest created by `weave create --from-windows`, then
  take the golden snapshot.

  weave's unattended install has already done the following at first logon, so
  this script does not repeat them:

    - the local admin account (weave/weave) and permanent autologon: its answer
      file sets AutoAdminLogon and deletes AutoLogonCount, so the console session
      is present after every boot and every snapshot revert;
    - OpenSSH server, installed and started, retried across reboots because the
      capability pull takes about nine minutes;
    - the static NIC configuration the HCS backend needs, as it has no DHCP.

  Do not pass --unattend-file when creating the guest. It replaces weave's answer
  file, and with it the SSH enablement and the setup-complete signal `weave run`
  waits on.

  No Go toolchain is installed: the binary under test is built on the host and
  pushed in per run, so the guest cannot serve a stale build.

  Snapshot after running this, not before. A revert removes everything below,
  which is the isolation the suite relies on.
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
# The suite skips its UI scenarios when this is missing, rather than running them
# in session 0 where there is no desktop.
$src = Join-Path $PSScriptRoot 'run-interactive.ps1'
$dst = Join-Path $WorkDir 'run-interactive.ps1'
if (-not (Test-Path -LiteralPath $src)) {
  Write-Warning "run-interactive.ps1 not found next to this script; copy it to $WorkDir by hand"
} elseif ((Resolve-Path $src).Path -eq (Resolve-Path -ErrorAction SilentlyContinue $dst).Path) {
  # This script was itself delivered into the work directory, so the runner is
  # already where it belongs. Copy-Item onto itself is an error, not a no-op.
  Write-Host '    already in place'
} else {
  Copy-Item -LiteralPath $src -Destination $dst -Force
}
[Environment]::SetEnvironmentVariable('ACC_INTERACTIVE_USER', $InteractiveUser, 'Machine')

Step 'fix the parts of the desktop that would otherwise vary between runs'
$explorer = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
New-ItemProperty -Path $explorer -Name 'HideFileExt' -Value 0 -PropertyType DWord -Force | Out-Null
# No screen saver and no sleep: the lock screen runs on the secure desktop, which
# cannot be automated at all.
Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'ScreenSaveActive' -Value '0'
powercfg /change monitor-timeout-ac 0
powercfg /change standby-timeout-ac 0
# Automatic updates can reboot the guest mid-run.
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
  $problems += "sshd is not installed. weave's first-logon setup installs it and logs to " +
               "C:\Windows\Temp\weave-setup.log."
} elseif ($sshd.Status -ne 'Running') {
  $problems += "sshd is $($sshd.Status); see C:\Windows\Temp\weave-setup.log"
}
if (-not (Test-Path (Join-Path $WorkDir 'run-interactive.ps1'))) {
  $problems += 'the interactive runner is missing'
}
# weave's autologon establishes this session. Its absence usually means the guest
# was created with a --unattend-file that replaced weave's answer file.
if (-not ((query user 2>$null) -match $InteractiveUser)) {
  $problems += "no console session for '$InteractiveUser'; check whether the guest was " +
               "created with --unattend-file."
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
