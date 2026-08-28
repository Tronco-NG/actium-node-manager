[CmdletBinding()]
param(
    [ValidateSet('lab', 'stable')][string]$Channel = 'lab'
)

$ErrorActionPreference = 'Stop'
$installerRoot = Split-Path -Parent $PSScriptRoot
$tauriRoot = Join-Path $installerRoot 'src-tauri'
$artifactDir = Join-Path $tauriRoot 'target\release\bundle\supervisor'
$payload = Join-Path $tauriRoot 'resources\node'
$manifest = Join-Path $payload 'PAYLOAD.json'
if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
    throw 'Falta resources/node/PAYLOAD.json. Ejecute el prepare de payload del canal antes del build.'
}
$payloadManifest = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
if ($payloadManifest.schema -ne 3 -or $payloadManifest.productChannel -ne $Channel) {
    throw "El payload preparado no pertenece al canal $Channel o no usa schema 3."
}
$env:ACTIUM_PRODUCT_CHANNEL = $Channel
& node (Join-Path $PSScriptRoot 'verify-payload-identity.mjs') $payload
if ($LASTEXITCODE -ne 0) { throw 'La identidad del payload Supervisor no coincide con HEAD.' }

& cargo build --release --manifest-path (Join-Path $tauriRoot 'Cargo.toml') -p actium-node-supervisor
if ($LASTEXITCODE -ne 0) { throw 'cargo build del Supervisor Windows fallo.' }

$version = '0.5.20'
$packageName = "actium-node-supervisor-$version-$Channel-windows-x86_64"
$stage = Join-Path ([IO.Path]::GetTempPath()) ("actium-supervisor-" + [Guid]::NewGuid())
$packageRoot = Join-Path $stage $packageName
New-Item -ItemType Directory -Path (Join-Path $packageRoot 'payload') -Force | Out-Null
New-Item -ItemType Directory -Path $artifactDir -Force | Out-Null
try {
    Copy-Item -LiteralPath (Join-Path $tauriRoot 'target\release\actium-node-supervisor.exe') -Destination $packageRoot
    foreach ($file in @('install-supervisor-windows.ps1', 'uninstall-supervisor-windows.ps1', 'supervisor.windows.toml.template', 'README.md')) {
        Copy-Item -LiteralPath (Join-Path $tauriRoot "supervisor\$file") -Destination $packageRoot
    }
    Copy-Item -Path (Join-Path $payload '*') -Destination (Join-Path $packageRoot 'payload') -Recurse
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
