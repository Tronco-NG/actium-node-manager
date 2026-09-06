[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$outputRoot = Join-Path $projectRoot 'dist/installers/linux'
$imageName = 'actium-telemetry-node-installer-linux-builder:local'
$containerName = "actium-installer-export-$([Guid]::NewGuid().ToString('N').Substring(0, 10))"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Docker no esta disponible en PATH.' }
& docker info *> $null
if ($LASTEXITCODE -ne 0) { throw 'Docker Desktop no esta operativo.' }

Push-Location $projectRoot
try {
    & docker build --file (Join-Path $projectRoot 'linux-builder.Dockerfile') --tag $imageName .
    if ($LASTEXITCODE -ne 0) { throw "Docker build finalizo con codigo $LASTEXITCODE." }
    & docker create --name $containerName $imageName | Out-Null
    [System.IO.Directory]::CreateDirectory($outputRoot) | Out-Null
    & docker cp "${containerName}:/actium-installer-artifacts/." $outputRoot
    if ($LASTEXITCODE -ne 0) { throw 'No se pudieron extraer los paquetes Linux.' }
    $checksums = Get-ChildItem -LiteralPath $outputRoot -File | Where-Object { $_.Name -ne 'SHA256SUMS' } | ForEach-Object {
        $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $($_.Name)"
    }
    [System.IO.File]::WriteAllLines((Join-Path $outputRoot 'SHA256SUMS'), $checksums, [System.Text.UTF8Encoding]::new($false))
    Write-Host "Instaladores Linux disponibles en $outputRoot"
} finally {
    & docker rm -f $containerName *> $null
    Pop-Location
}
