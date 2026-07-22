[CmdletBinding()]
param([switch]$SkipInstall)

$ErrorActionPreference = 'Stop'
$installerRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$dataPlaneRoot = Split-Path -Parent $installerRoot
$outputRoot = Join-Path $dataPlaneRoot 'dist/installers/windows'

Push-Location $installerRoot
try {
    if (-not $SkipInstall) { & npm.cmd ci }
    & npm.cmd run tauri:build -- --bundles nsis,msi
    if ($LASTEXITCODE -ne 0) { throw "Tauri build finalizo con codigo $LASTEXITCODE." }

    [System.IO.Directory]::CreateDirectory($outputRoot) | Out-Null
    foreach ($bundle in @('nsis', 'msi')) {
        $source = Join-Path $installerRoot "src-tauri/target/release/bundle/$bundle"
        if (Test-Path -LiteralPath $source -PathType Container) {
            Copy-Item -Path (Join-Path $source '*') -Destination $outputRoot -Force
        }
    }
    $checksums = Get-ChildItem -LiteralPath $outputRoot -File | Where-Object { $_.Name -ne 'SHA256SUMS' } | ForEach-Object {
        $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $($_.Name)"
    }
    [System.IO.File]::WriteAllLines((Join-Path $outputRoot 'SHA256SUMS'), $checksums, [System.Text.UTF8Encoding]::new($false))
    Write-Host "Instaladores Windows disponibles en $outputRoot"
} finally {
    Pop-Location
}
