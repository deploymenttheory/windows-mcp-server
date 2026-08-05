<#
.SYNOPSIS
  Prepare a fresh Windows guest to host the acceptance suite, then stop.

.DESCRIPTION
  Run this once inside a guest created by `weave create --from-windows`, then
  take the golden snapshot. It is idempotent, so re-running it after a partial
  failure is safe.

  It deliberately does NOT install a Go toolchain: the binary under test is built
  on the host and pushed in per run, so the guest never has to match the host's
  toolchain and a run cannot accidentally test a stale in-guest build.

  Snapshot AFTER running this. Reverting removes everything below along with
  everything else, which is the property the suite relies on for isolation — and
  the reason a snapshot taken before provisioning is useless.
#>
[CmdletBinding()]
param(
  [string]$WorkDir = 'C:\acc',
  [string]$InteractiveUser = 'acc'
)

$ErrorActionPreference = 'Stop'

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

Step "work directory at $WorkDir"
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

Step 'OpenSSH server'
# weave ssh needs sshd, and a fresh Windows image does not have it running.
$cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' |
  Where-Object State -ne 'Installed'
if ($cap) { $cap | Add-WindowsCapability -Online | Out-Null }
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd -ErrorAction SilentlyContinue

Step 'the interactive runner'
# Copy the runner next to the work directory. The suite looks for it here and
# skips the UI scenarios if it is missing, rather than running them in session 0
# and failing for the wrong reason.
$src = Join-Path $PSScriptRoot 'run-interactive.ps1'
if (Test-Path -LiteralPath $src) {
  Copy-Item -LiteralPath $src -Destination (Join-Path $WorkDir 'run-interactive.ps1') -Force
} else {
  Write-Warning "run-interactive.ps1 not found next to this script; copy it to $WorkDir by hand"
}
[Environment]::SetEnvironmentVariable('ACC_INTERACTIVE_USER', $InteractiveUser, 'Machine')

Step 'a desktop worth automating'
# Notepad is what the shipped example journey drives. On recent images it is a
# Store app that may not be present on a minimal install.
if (-not (Get-Command notepad.exe -ErrorAction SilentlyContinue)) {
  Write-Warning 'notepad.exe not found; the example journey will not run on this image'
}

Step 'turn off what makes a desktop unpredictable'
# Every one of these is a source of a UI test failing for a reason that has
# nothing to do with the code under test.
$explorer = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
New-ItemProperty -Path $explorer -Name 'HideFileExt' -Value 0 -PropertyType DWord -Force | Out-Null
# No screen saver, no lock: a locked desktop cannot be automated at all, and the
# secure desktop is a documented non-goal rather than something to work around.
Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'ScreenSaveActive' -Value '0'
powercfg /change monitor-timeout-ac 0
powercfg /change standby-timeout-ac 0
# Windows Update deciding to reboot mid-suite is the classic overnight failure.
$au = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
New-Item -Path $au -Force | Out-Null
New-ItemProperty -Path $au -Name 'NoAutoUpdate' -Value 1 -PropertyType DWord -Force | Out-Null

Step 'verify'
$problems = @()
if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) { $problems += 'sshd is not installed' }
if (-not (Test-Path (Join-Path $WorkDir 'run-interactive.ps1'))) { $problems += 'the interactive runner is missing' }
# The one thing this script cannot arrange for itself: an interactive session.
# It comes from autologon in the unattend answer file at install time.
$console = (query user 2>$null) -match $InteractiveUser
if (-not $console) {
  $problems += "no console session for '$InteractiveUser' — autologon is not in effect. " +
               "It belongs in the unattend answer file (acceptance/guest/autologon.xml), " +
               "not armed after the fact."
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
