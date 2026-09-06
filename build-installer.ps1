[CmdletBinding()]
param([switch]$SkipInstall)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$outputRoot = Join-Path $projectRoot 'dist/installers/windows'
$installerVersion = (Get-Content -LiteralPath (Join-Path $projectRoot 'package.json') -Raw | ConvertFrom-Json).version

Push-Location $projectRoot
try {
    if (-not $SkipInstall) { & npm.cmd ci }
    & npm.cmd run tauri:build -- --bundles nsis,msi
    if ($LASTEXITCODE -ne 0) { throw "Tauri build finalizo con codigo $LASTEXITCODE." }

    [System.IO.Directory]::CreateDirectory($outputRoot) | Out-Null
    Get-ChildItem -LiteralPath $outputRoot -File | Where-Object {
        $_.Name -like 'Actium Telemetry Node Installer_*' -or $_.Name -eq 'SHA256SUMS'
    } | Remove-Item -Force
    foreach ($bundle in @('nsis', 'msi')) {
        $source = Join-Path $projectRoot "src-tauri/target/release/bundle/$bundle"
        if (Test-Path -LiteralPath $source -PathType Container) {
            Get-ChildItem -LiteralPath $source -File | Where-Object {
                $_.Name -like "Actium Telemetry Node Installer_${installerVersion}_*"
            } | Copy-Item -Destination $outputRoot -Force
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
