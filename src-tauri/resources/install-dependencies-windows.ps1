[CmdletBinding()]
param([switch]$Elevated)

$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $PSCommandPath + '"'), '-Elevated')
    $process = Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $arguments -Wait -PassThru
    exit $process.ExitCode
}

if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
    throw 'Windows Package Manager (winget) no esta disponible. Instale App Installer desde Microsoft Store y vuelva a intentar.'
}

$wslReady = $false
try {
    & wsl.exe --status *> $null
    $wslReady = ($LASTEXITCODE -eq 0)
} catch { $wslReady = $false }

if (-not $wslReady) {
    Write-Host 'Habilitando WSL 2 para Docker Desktop...'
    & wsl.exe --install --no-distribution
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo habilitar WSL 2.' }
}

Write-Host 'Instalando o actualizando Docker Desktop y Docker Compose...'
& winget.exe install --id Docker.DockerDesktop --exact --accept-package-agreements --accept-source-agreements --silent
if ($LASTEXITCODE -ne 0) { throw 'winget no pudo instalar Docker Desktop.' }

Write-Host 'Docker Desktop fue instalado. Abra Docker Desktop y, si Windows lo solicita, reinicie el equipo.'
