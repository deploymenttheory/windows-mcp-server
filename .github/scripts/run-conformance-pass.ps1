<#
.SYNOPSIS
Runs one pass of the official MCP conformance suite against a freshly-started
conformance host, then stops it.

.DESCRIPTION
The host's lifetime is deliberately scoped to this script rather than spread
across workflow steps. A Windows runner terminates a step's process tree when the
step ends, so a host started in an earlier step is already gone by the time the
suite runs. Every request then fails to connect and the suite reports the server
as wholly non-conformant — which looks like a catastrophic protocol failure and
is actually an empty socket.

Readiness is proved with a real server/discover POST rather than a TCP connect or
a GET. Under the stateless transport a GET returns 405, and a TCP connect only
proves the listener exists, not that the MCP surface behind it answers.

.NOTES
Exits with the suite's own exit code: 0 when every result matched the baseline,
1 on an unexpected failure or a stale baseline entry.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$HostExe,
    [Parameter(Mandatory)][int]$Port,
    [Parameter(Mandatory)][string]$SpecVersion,
    [Parameter(Mandatory)][string]$HarnessVersion,
    [Parameter(Mandatory)][string]$Baseline,
    [Parameter(Mandatory)][string]$OutputDir,
    [Parameter(Mandatory)][string]$LogDir,
    [switch]$Fixtures
)

$ErrorActionPreference = 'Stop'

# Any terminating error below must leave a non-zero exit code. Without this the
# script can die on a throw — a host that never starts, a missing harness — while
# PowerShell still reports success to the runner, and the step goes green having
# verified nothing. That is the failure this whole workflow exists to avoid, so
# it must not be reintroduced by the runner script itself.
trap {
    Write-Host "::error::conformance pass '$Name' failed: $_"
    exit 1
}

$hostArgs = @('conformance-serve', '--addr', "127.0.0.1:$Port")
if ($Fixtures) { $hostArgs += '--fixtures' }

$stdout = Join-Path $LogDir "$Name.out"
$stderr = Join-Path $LogDir "$Name.err"

Write-Host "starting conformance host for '$Name' on 127.0.0.1:$Port (fixtures=$($Fixtures.IsPresent))"
$proc = Start-Process -FilePath $HostExe -ArgumentList $hostArgs `
    -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru

$exitCode = 1
try {
    # A conformant stateless request: the _meta triple plus the standard headers.
    $body = '{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{' +
            '"io.modelcontextprotocol/protocolVersion":"' + $SpecVersion + '",' +
            '"io.modelcontextprotocol/clientCapabilities":{}}}}'
    $headers = @{
        'Mcp-Method'           = 'server/discover'
        'Mcp-Protocol-Version' = $SpecVersion
        'Accept'               = 'application/json, text/event-stream'
    }

    $ready = $false
    foreach ($attempt in 1..40) {
        if ($proc.HasExited) {
            Get-Content $stderr -ErrorAction SilentlyContinue
            throw "conformance host for '$Name' exited during startup (code $($proc.ExitCode))"
        }
        try {
            $res = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/mcp" -Method Post `
                -Headers $headers -ContentType 'application/json' -Body $body `
                -UseBasicParsing -TimeoutSec 5
            if ($res.StatusCode -eq 200) { $ready = $true; break }
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $ready) {
        Get-Content $stderr -ErrorAction SilentlyContinue
        throw "conformance host for '$Name' never became ready on port $Port"
    }
    Write-Host "host for '$Name' ready; running the suite at spec $SpecVersion"

    # --suite all, not active: the harness classifies 2026-07-28 as its draft
    # revision, so `active` excludes exactly the scenarios that revision added.
    npx -y "@modelcontextprotocol/conformance@$HarnessVersion" server `
        --url "http://127.0.0.1:$Port/mcp" `
        --suite all --spec-version $SpecVersion `
        --expected-failures $Baseline `
        --output-dir $OutputDir
    $exitCode = $LASTEXITCODE
} finally {
    if (-not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
    # The host's own log is evidence too: it carries the audit chain for the run.
    if (Test-Path $stderr) {
        Write-Host "--- conformance host log ($Name) ---"
        Get-Content $stderr -Tail 40
    }
}

Write-Host "pass '$Name' finished with exit code $exitCode"
exit $exitCode
