<#
.SYNOPSIS
  Run a command in the guest's interactive console session and return its output.

.DESCRIPTION
  A command sent over SSH runs in session 0, a service context with no window
  station. UI Automation needs a desktop, so every UIA call there fails or
  returns nothing. Anything that drives the UI — a journey run, a Snapshot,
  credential injection — has to run in the logged-on user's console session.

  The handover is a scheduled task with an Interactive logon type, which the task
  scheduler runs in that session. Output and exit code are written to files,
  because a task's stdout is not returned to whoever started it.

.PARAMETER Command
  The PowerShell command to run in the console session.

.PARAMETER WorkDir
  Working directory for the command. Defaults to C:\acc.

.PARAMETER TimeoutSec
  How long to wait for the task to finish before giving up.

.EXAMPLE
  .\run-interactive.ps1 -Command "& 'C:\acc\windows-mcp-server.exe' journey run j.json --json"
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Command,
  [string]$WorkDir = 'C:\acc',
  [int]$TimeoutSec = 300
)

$ErrorActionPreference = 'Stop'

# The account whose console session receives the command. weave's unattended
# install creates it and sets permanent autologon, so the session is present
# after every boot and every snapshot revert.
$targetUser = $env:ACC_INTERACTIVE_USER
if ([string]::IsNullOrWhiteSpace($targetUser)) { $targetUser = 'weave' }

$taskName = "windows-mcp-acc-$([guid]::NewGuid().ToString('N').Substring(0,8))"
$stateDir = Join-Path $WorkDir 'interactive'
New-Item -ItemType Directory -Force -Path $stateDir | Out-Null

$scriptPath = Join-Path $stateDir "$taskName.ps1"
$outPath    = Join-Path $stateDir "$taskName.out"
$codePath   = Join-Path $stateDir "$taskName.code"

# Wrap the command so its output and exit code both land on disk, which is the
# only channel back to the caller.
@"
Set-Location -LiteralPath '$WorkDir'
try {
  `$out = & { $Command } 2>&1 | Out-String
  Set-Content -LiteralPath '$outPath' -Value `$out -Encoding UTF8
  Set-Content -LiteralPath '$codePath' -Value '0' -Encoding UTF8
} catch {
  Set-Content -LiteralPath '$outPath' -Value (`$_ | Out-String) -Encoding UTF8
  Set-Content -LiteralPath '$codePath' -Value '1' -Encoding UTF8
}
"@ | Set-Content -LiteralPath $scriptPath -Encoding UTF8

try {
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$scriptPath`""
  # LogonType Interactive puts the task in the logged-on user's session rather
  # than in session 0 alongside this script.
  $principal = New-ScheduledTaskPrincipal -UserId $targetUser -LogonType Interactive -RunLevel Limited
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::FromSeconds($TimeoutSec + 60))

  Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal `
    -Settings $settings | Out-Null
  Start-ScheduledTask -TaskName $taskName

  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ((Get-Date) -lt $deadline) {
    if (Test-Path -LiteralPath $codePath) { break }
    Start-Sleep -Milliseconds 500
  }

  if (-not (Test-Path -LiteralPath $codePath)) {
    throw "the interactive command did not finish within ${TimeoutSec}s. " +
          "Check that '$targetUser' is logged on at the console — without an " +
          "interactive session there is nothing for the task to run in."
  }

  if (Test-Path -LiteralPath $outPath) {
    Get-Content -Raw -LiteralPath $outPath
  }
  $code = (Get-Content -Raw -LiteralPath $codePath).Trim()
  if ($code -ne '0') { exit 1 }
}
finally {
  Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
}
