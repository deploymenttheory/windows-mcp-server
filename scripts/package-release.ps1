param(
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$RepositoryRoot,
    [Parameter(Mandatory = $true)][string]$ManifestPath,
    [Parameter(Mandatory = $true)][string]$DistDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9.-]+)?$') {
    throw "Invalid release version: $Version"
}

$repo = (Resolve-Path $RepositoryRoot).Path
$dist = (Resolve-Path $DistDir).Path
$metadata = Get-Content -Raw (Join-Path $dist 'metadata.json') | ConvertFrom-Json
if ($metadata.version -ne $Version) {
    throw "GoReleaser built $($metadata.version), expected $Version"
}

$artifacts = Get-Content -Raw (Join-Path $dist 'artifacts.json') | ConvertFrom-Json

function Get-Binary([string]$arch) {
    $matches = @($artifacts | Where-Object { $_.type -eq 'Binary' -and $_.goos -eq 'windows' -and $_.goarch -eq $arch })
    if ($matches.Count -ne 1) {
        throw "Expected one Windows $arch binary, found $($matches.Count)"
    }
    $path = Join-Path $repo $matches[0].path
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "GoReleaser binary missing: $path"
    }
    return $path
}

function Assert-ZipBinary([string]$zipPath, [string]$entryName, [string]$binary) {
    Add-Type -AssemblyName System.IO.Compression
    $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
    try {
        $entry = $zip.GetEntry($entryName)
        if ($null -eq $entry) { throw "$zipPath has no $entryName" }
        $stream = $entry.Open()
        try {
            $packedHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream))
        } finally {
            $stream.Dispose()
        }
        $sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $binary).Hash
        if ($packedHash -ne $sourceHash) {
            throw "$zipPath contains a different binary from $binary"
        }
    } finally {
        $zip.Dispose()
    }
}

foreach ($arch in @('amd64', 'arm64')) {
    $binary = Get-Binary $arch
    $archive = Join-Path $dist "windows-mcp-server_${Version}_windows_${arch}.zip"
    $stage = Join-Path ([IO.Path]::GetTempPath()) ("windows-release-" + [guid]::NewGuid().ToString('N'))
    try {
        New-Item -ItemType Directory -Path (Join-Path $stage 'policy/examples') -Force | Out-Null
        Copy-Item -LiteralPath $binary -Destination (Join-Path $stage 'windows-mcp-server.exe')
        Copy-Item -LiteralPath (Join-Path $repo 'README.md') -Destination $stage
        Copy-Item -LiteralPath (Join-Path $repo 'LICENSE') -Destination $stage
        Copy-Item -Path (Join-Path $repo 'policy/examples/*.json') -Destination (Join-Path $stage 'policy/examples')
        Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -CompressionLevel Optimal -Force
        Assert-ZipBinary $archive 'windows-mcp-server.exe' $binary
    } finally {
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# MCPB 0.3 has an OS selector but no architecture selector. The Desktop bundle
# carries amd64; both architectures remain available as direct release ZIPs.
$bundleBinary = Get-Binary 'amd64'
$bundle = Join-Path $dist "windows-mcp-server_${Version}_windows_amd64.mcpb"
$stage = Join-Path ([IO.Path]::GetTempPath()) ("windows-mcpb-" + [guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path (Join-Path $stage 'server') -Force | Out-Null
    Copy-Item -LiteralPath $bundleBinary -Destination (Join-Path $stage 'server/windows-mcp-server.exe')
    $manifest = Get-Content -Raw -LiteralPath $ManifestPath | ConvertFrom-Json
    $manifest.version = $Version
    $manifest | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $stage 'manifest.json') -Encoding utf8
    & mcpb validate $stage
    if ($LASTEXITCODE -ne 0) { throw 'MCPB manifest validation failed' }
    & mcpb pack $stage $bundle
    if ($LASTEXITCODE -ne 0) { throw 'MCPB packaging failed' }
    Assert-ZipBinary $bundle 'server/windows-mcp-server.exe' $bundleBinary
} finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Output "Packaged Windows amd64/arm64 archives and amd64 MCPB for $Version"
