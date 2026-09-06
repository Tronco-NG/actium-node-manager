[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [string]$Payload,
    [ValidateSet('lab', 'stable')][string]$Channel = 'lab',
    [switch]$NoStart
)

$ErrorActionPreference = 'Stop'
trap {
    Write-Host "`n===============================================================" -ForegroundColor Red
    Write-Host "   ERROR CRITICO DURANTE LA INSTALACION DEL SUPERVISOR" -ForegroundColor Red
    Write-Host "===============================================================" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Yellow
    Write-Host "`nPresione cualquier tecla para salir..." -ForegroundColor Cyan
    try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { }
    exit 1
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Ejecute este instalador desde PowerShell como Administrador.'
}

$binaryPath = (Resolve-Path -LiteralPath $Binary).Path
$payloadPath = $null
if (-not [string]::IsNullOrWhiteSpace($Payload)) {
    $payloadPath = (Resolve-Path -LiteralPath $Payload).Path
    if (-not (Test-Path -LiteralPath (Join-Path $payloadPath 'PAYLOAD.json') -PathType Leaf)) {
        throw 'El bundle externo no contiene PAYLOAD.json.'
    }
}

$isLab = $Channel -eq 'lab'
$serviceName = if ($isLab) { 'ActiumNodeSupervisorLab' } else { 'ActiumNodeSupervisor' }
$rootName = if ($isLab) { 'NodeManagerLab' } else { 'NodeManager' }
$root = Join-Path $env:ProgramData "Actium\$rootName"
$configDir = Join-Path $root 'config'
$stateDir = Join-Path $root 'state'
$nodesRoot = Join-Path $root 'nodes'
$fabricsRoot = Join-Path $root 'fabrics'
$hostIdentityRoot = Join-Path $env:ProgramData 'Actium\NodeManager\identity'
$payloadTarget = Join-Path $root 'payload'
$payloadNext = Join-Path $root 'payload.next'
$payloadPrevious = Join-Path $root 'payload.previous'
$binaryDir = Join-Path $root 'bin'
$installedBinary = Join-Path $binaryDir 'actium-node-supervisor.exe'
$binaryNext = Join-Path $binaryDir 'actium-node-supervisor.next.exe'
$binaryPrevious = Join-Path $binaryDir 'actium-node-supervisor.previous.exe'
$configPath = Join-Path $configDir 'supervisor.toml'
$keyPath = Join-Path $configDir 'ipc.key'
$markerPath = Join-Path $stateDir 'root-ownership.json'
$operatorGroup = 'ActiumNodeOperators'

function Protect-ActiumSecretTree {
    param([Parameter(Mandatory = $true)][string]$SecretRoot)
    if (-not (Test-Path -LiteralPath $SecretRoot -PathType Container)) { return }
    $resolved = (Resolve-Path -LiteralPath $SecretRoot).Path
    if (-not ($resolved.StartsWith($nodesRoot, [StringComparison]::OrdinalIgnoreCase) -or
              $resolved.StartsWith($fabricsRoot, [StringComparison]::OrdinalIgnoreCase))) {
        throw "Directorio secrets fuera del root autorizado: $resolved"
    }
    & icacls.exe $resolved /reset /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "No se pudo resetear DACL de $resolved" }
    & icacls.exe $resolved /inheritance:r /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "No se pudo proteger herencia de $resolved" }
    & icacls.exe $resolved /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "No se pudo restringir DACL de $resolved" }
}

& $binaryPath --self-test
if ($LASTEXITCODE -ne 0) { throw 'El self-test del Supervisor fallo.' }
if ($payloadPath) {
    & $binaryPath --verify-payload $payloadPath
    if ($LASTEXITCODE -ne 0) { throw 'El bundle externo schema 3 fue rechazado.' }
}

if (-not (Get-LocalGroup -Name $operatorGroup -ErrorAction SilentlyContinue)) {
    New-LocalGroup -Name $operatorGroup -Description 'Operadores locales de Actium Node Manager' | Out-Null
}
$group = Get-LocalGroup -Name $operatorGroup
$groupSid = $group.SID.Value
$pipeSddl = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)(A;;GRGW;;;$groupSid)"

try {
    Add-LocalGroupMember -Group $operatorGroup -Member $identity.Name -ErrorAction SilentlyContinue | Out-Null
} catch { }

foreach ($directory in @($configDir, $stateDir, $nodesRoot, $fabricsRoot, $hostIdentityRoot, $binaryDir, (Join-Path $root 'logs'))) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}

if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
    $marker = [ordered]@{
        schema = 1
        owner = 'actium-node-supervisor'
        productChannel = $Channel
        rootId = [Guid]::NewGuid().ToString()
        authorizedNodesRoot = $nodesRoot
        authorizedFabricsRoot = $fabricsRoot
        confirmedAt = [DateTimeOffset]::UtcNow.ToString('O')
        confirmedBy = $identity.Name
    }
    $json = $marker | ConvertTo-Json
    [IO.File]::WriteAllText($markerPath, $json, [Text.UTF8Encoding]::new($false))
}

if (-not (Test-Path -LiteralPath $keyPath -PathType Leaf)) {
    $bytes = New-Object byte[] 48
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    $rng.GetBytes($bytes)
    [IO.File]::WriteAllText($keyPath, [Convert]::ToBase64String($bytes), [Text.UTF8Encoding]::new($false))
}

$templateCandidates = @(
    (Join-Path $PSScriptRoot 'supervisor.windows.toml.template'),
    (Join-Path (Split-Path -Parent $binaryPath) 'supervisor.windows.toml.template'),
    (Join-Path (Split-Path -Parent $binaryPath) 'supervisor\supervisor.windows.toml.template'),
    (Join-Path $env:ProgramFiles 'Actium Node Manager\resources\supervisor\supervisor.windows.toml.template')
)
$templatePath = $templateCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not $templatePath) {
    throw 'No se pudo encontrar supervisor.windows.toml.template en las rutas de instalacion.'
}
$rootToml = $root.Replace('\', '/')
$hostIdentityRootToml = $hostIdentityRoot.Replace('\', '/')
$fabricProject = if ($isLab) { 'actium-lab-fabric-01' } else { 'actium-node-fabric-01' }
$config = (Get-Content -LiteralPath $templatePath -Raw)
$config = $config.Replace('__CHANNEL__', $Channel)
$config = $config.Replace('__PIPE_NAME__', $serviceName)
$config = $config.Replace('__PIPE_SDDL__', $pipeSddl)
$config = $config.Replace('__SERVICE_NAME__', $serviceName)
$config = $config.Replace('__ROOT__', $rootToml)
$config = $config.Replace('__HOST_IDENTITY_ROOT__', $hostIdentityRootToml)
$config = $config.Replace('__FABRIC_PROJECT__', $fabricProject)
[IO.File]::WriteAllText($configPath, $config, [Text.UTF8Encoding]::new($false))

# Permisos: SYSTEM y Admins control total; Operadores y Usuarios Autenticados lectura/ejecucion
& icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*$groupSid`:(OI)(CI)RX" '*S-1-5-11:(OI)(CI)RX' | Out-Null
& icacls.exe $hostIdentityRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
& icacls.exe $nodesRoot /grant "*$groupSid`:(OI)(CI)RX" '*S-1-5-11:(OI)(CI)RX' | Out-Null
& icacls.exe $fabricsRoot /grant "*$groupSid`:(OI)(CI)RX" '*S-1-5-11:(OI)(CI)RX' | Out-Null
& icacls.exe $keyPath /grant "*$groupSid`:R" '*S-1-5-11:R' | Out-Null
Get-ChildItem -LiteralPath @($nodesRoot, $fabricsRoot) -Directory -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -eq 'secrets' } |
    ForEach-Object { Protect-ActiumSecretTree -SecretRoot $_.FullName }

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
$wasRunning = $service -and $service.Status -eq 'Running'
if ($service -and $service.Status -ne 'Stopped') {
    Stop-Service -Name $serviceName -Force
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
}

Copy-Item -LiteralPath $binaryPath -Destination $binaryNext -Force
if ($payloadPath) {
    if (Test-Path -LiteralPath $payloadNext) { Remove-Item -LiteralPath $payloadNext -Recurse -Force }
    Copy-Item -LiteralPath $payloadPath -Destination $payloadNext -Recurse
}

if (Test-Path -LiteralPath $binaryPrevious) { Remove-Item -LiteralPath $binaryPrevious -Force }
if (Test-Path -LiteralPath $installedBinary) { Move-Item -LiteralPath $installedBinary -Destination $binaryPrevious }
Move-Item -LiteralPath $binaryNext -Destination $installedBinary
if ($payloadPath) {
    if (Test-Path -LiteralPath $payloadPrevious) { Remove-Item -LiteralPath $payloadPrevious -Recurse -Force }
    if (Test-Path -LiteralPath $payloadTarget) { Move-Item -LiteralPath $payloadTarget -Destination $payloadPrevious }
    Move-Item -LiteralPath $payloadNext -Destination $payloadTarget
}

$serviceCommand = '"{0}" --service --config "{1}"' -f $installedBinary, $configPath
if ($service) {
    & sc.exe config $serviceName binPath= $serviceCommand start= auto | Out-Null
} else {
    & sc.exe create $serviceName binPath= $serviceCommand start= auto DisplayName= "Actium Node Supervisor ($Channel)" | Out-Null
}

try {
    & $installedBinary --config $configPath --check
    if ($LASTEXITCODE -ne 0) { throw 'El check owner-confirmed del Supervisor fallo.' }
} catch {
    if (Test-Path -LiteralPath $binaryPrevious) {
        Remove-Item -LiteralPath $installedBinary -Force -ErrorAction SilentlyContinue
        Move-Item -LiteralPath $binaryPrevious -Destination $installedBinary
    }
    if ($payloadPath -and (Test-Path -LiteralPath $payloadPrevious)) {
        Remove-Item -LiteralPath $payloadTarget -Recurse -Force -ErrorAction SilentlyContinue
        Move-Item -LiteralPath $payloadPrevious -Destination $payloadTarget
    }
    if ($wasRunning) { Start-Service -Name $serviceName }
    throw
}

if (-not $NoStart) {
    try {
        Start-Service -Name $serviceName -ErrorAction SilentlyContinue
        $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($svc.Status -ne 'Running') {
            & sc.exe start $serviceName | Out-Null
        }
    } catch { }
}

Write-Host "Actium Node Supervisor 0.5.21 ($Channel) instalado exitosamente en $root" -ForegroundColor Green
Write-Host "Servicio registrado y activo: $serviceName" -ForegroundColor Green
Start-Sleep -Seconds 2
