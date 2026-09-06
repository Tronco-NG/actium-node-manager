[CmdletBinding()]
param(
    [ValidateSet('lab', 'stable')][string]$Channel = 'lab',
    [string]$PayloadPath = ''
)

$ErrorActionPreference = 'Stop'
$installerRoot = Split-Path -Parent $PSScriptRoot
$tauriRoot = Join-Path $installerRoot 'src-tauri'
$artifactDir = Join-Path $tauriRoot 'target\release\bundle\supervisor'
$payload = if ([string]::IsNullOrWhiteSpace($PayloadPath)) {
    Join-Path $tauriRoot 'resources\node'
} else {
    [IO.Path]::GetFullPath($PayloadPath)
}
$manifest = Join-Path $payload 'PAYLOAD.json'
$payloadAvailable = Test-Path -LiteralPath $manifest -PathType Leaf
if (-not [string]::IsNullOrWhiteSpace($PayloadPath) -and -not $payloadAvailable) {
    throw "El bundle externo no contiene PAYLOAD.json: $payload"
}
if ($payloadAvailable) {
    $payloadManifest = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
    if ($payloadManifest.schema -ne 3) {
        throw 'El payload preparado no usa schema 3.'
    }
}
$env:ACTIUM_PRODUCT_CHANNEL = $Channel
if ($payloadAvailable) {
    & node (Join-Path $PSScriptRoot 'verify-payload-identity.mjs') $payload
    if ($LASTEXITCODE -ne 0) { throw 'La identidad del payload Supervisor no coincide con HEAD.' }
}

& cargo build --release --manifest-path (Join-Path $tauriRoot 'Cargo.toml') -p actium-node-supervisor
if ($LASTEXITCODE -ne 0) { throw 'cargo build del Supervisor Windows fallo.' }

$version = '0.5.21'
$packageName = "actium-node-supervisor-$version-windows-x86_64"
$stage = Join-Path ([IO.Path]::GetTempPath()) ("actium-supervisor-" + [Guid]::NewGuid())
$packageRoot = Join-Path $stage $packageName
New-Item -ItemType Directory -Path $packageRoot -Force | Out-Null
if ($payloadAvailable) {
    New-Item -ItemType Directory -Path (Join-Path $packageRoot 'payload') -Force | Out-Null
    Write-Host "Product Extension Bundle: $payload"
} else {
    Write-Host 'Product Extension Bundle: NO_EXTENSIONS (Base Runtime)'
}
New-Item -ItemType Directory -Path $artifactDir -Force | Out-Null
try {
    Copy-Item -LiteralPath (Join-Path $tauriRoot 'target\release\actium-node-supervisor.exe') -Destination $packageRoot
    foreach ($file in @('install-supervisor-windows.ps1', 'uninstall-supervisor-windows.ps1', 'supervisor.windows.toml.template', 'README.md')) {
        Copy-Item -LiteralPath (Join-Path $tauriRoot "supervisor\$file") -Destination $packageRoot
    }
    if ($payloadAvailable) {
        Copy-Item -Path (Join-Path $payload '*') -Destination (Join-Path $packageRoot 'payload') -Recurse
    }
    $zip = Join-Path $artifactDir "$packageName.zip"
    if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
    Compress-Archive -LiteralPath $packageRoot -DestinationPath $zip -CompressionLevel Optimal
    $stream = [IO.File]::OpenRead($zip)
    try {
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            $hash = ([BitConverter]::ToString($sha256.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
        } finally {
            $sha256.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
    [IO.File]::WriteAllText("$zip.sha256", "$hash  $([IO.Path]::GetFileName($zip))`n", [Text.UTF8Encoding]::new($false))
    Write-Host $zip
} finally {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
