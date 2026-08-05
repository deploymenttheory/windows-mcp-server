<#
.SYNOPSIS
  Run a command in the guest's interactive console session and return its output.

.DESCRIPTION
  Windows has two worlds, and this script is the bridge between them.

  A command sent over SSH runs in session 0, a service context with no desktop.
  UI Automation needs a real desktop: no window station, no accessibility tree,
  and every UIA call fails or returns nothing. So anything that drives the UI —
  a journey run, a Snapshot, credential injection into a live field — has to be
  handed to the session the auto-logged-on user owns.

  The handover is a scheduled task with an Interactive logon type, which the task
  scheduler runs in that user's console session. Output is captured to a file the
  caller can read back, because a task's stdout goes nowhere by default.

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

# The user whose console session we hand the command to. The golden image
# auto-logs this account on, which is the whole reason an interactive session
# exists to hand anything to.
$targetUser = $env:ACC_INTERACTIVE_USER
if ([string]::IsNullOrWhiteSpace($targetUser)) { $targetUser = 'acc' }

$taskName = "windows-mcp-acc-$([guid]::NewGuid().ToString('N').Substring(0,8))"
$stateDir = Join-Path $WorkDir 'interactive'
New-Item -ItemType Directory -Force -Path $stateDir | Out-Null

$scriptPath = Join-Path $stateDir "$taskName.ps1"
$outPath    = Join-Path $stateDir "$taskName.out"
$codePath   = Join-Path $stateDir "$taskName.code"

# Wrap the command so its output and exit code both land on disk. Without this
# the task runs, succeeds, and tells the caller nothing about what it did.
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
  # Interactive is the load-bearing word: it puts the task in the logged-on
  # user's session rather than in session 0 alongside this script.
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
