param(
    [Parameter(Mandatory = $true)][string]$Tag,
    [Parameter(Mandatory = $true)][string]$Bundle
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Tag -notmatch '^v([0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9.-]+)?)$') {
    throw "Invalid release tag: $Tag"
}
if (-not (Test-Path -LiteralPath $Bundle -PathType Leaf)) {
    throw "Released MCPB is missing: $Bundle"
}

$version = $Matches[1]
$name = 'io.github.deploymenttheory/windows-mcp-server'
$sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $Bundle).Hash.ToLowerInvariant()
$url = "https://github.com/deploymenttheory/windows-mcp-server/releases/download/$Tag/$(Split-Path $Bundle -Leaf)"
$work = Join-Path ([IO.Path]::GetTempPath()) ("windows-registry-" + [guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $work | Out-Null
    $server = @{
        '$schema' = 'https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json'
        name = $name
        title = 'Windows MCP Server'
        description = 'Local Windows desktop automation through MCP.'
        websiteUrl = 'https://github.com/deploymenttheory/windows-mcp-server'
        repository = @{ url = 'https://github.com/deploymenttheory/windows-mcp-server'; source = 'github' }
        version = $version
        packages = @(@{
            registryType = 'mcpb'
            identifier = $url
            fileSha256 = $sha
            transport = @{ type = 'stdio' }
        })
    }
    $jsonPath = Join-Path $work 'server.json'
    $server | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $jsonPath -Encoding utf8
    & mcp-publisher validate $jsonPath
    if ($LASTEXITCODE -ne 0) { throw 'MCP Registry metadata validation failed' }
    if ($env:MCP_REGISTRY_VALIDATE_ONLY -eq '1') {
        Write-Output 'MCP Registry metadata validated'
        return
    }

    & mcp-publisher login github-oidc
    if ($LASTEXITCODE -ne 0) { throw 'MCP Registry OIDC login failed' }
    & mcp-publisher publish $jsonPath
    if ($LASTEXITCODE -eq 0) { return }

    # An immutable version may already exist after a retry. Confirm its bytes.
    $registryUrl = "https://registry.modelcontextprotocol.io/v0.1/servers/io.github.deploymenttheory%2Fwindows-mcp-server/versions/$version"
    try {
        $existing = Invoke-RestMethod -Uri $registryUrl -TimeoutSec 20
        $hashes = @($existing.server.packages | Where-Object registryType -eq 'mcpb' | ForEach-Object fileSha256)
        if ($hashes.Count -eq 1 -and $hashes[0] -eq $sha) {
            Write-Output "MCP Registry already has $name@$version with the matching bundle"
            return
        }
    } catch {
        Write-Warning "Registry lookup failed: $_"
    }
    throw "MCP Registry publication failed or $name@$version differs from this bundle"
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
