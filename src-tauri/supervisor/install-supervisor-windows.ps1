[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [Parameter(Mandatory = $true)][string]$Payload,
    [ValidateSet('lab', 'stable')][string]$Channel = 'lab',
    [switch]$NoStart
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Ejecute este instalador desde PowerShell como Administrador.'
}

$binaryPath = (Resolve-Path -LiteralPath $Binary).Path
$payloadPath = (Resolve-Path -LiteralPath $Payload).Path
if (-not (Test-Path -LiteralPath (Join-Path $payloadPath 'PAYLOAD.json') -PathType Leaf)) {
    throw 'Payload no contiene PAYLOAD.json.'
}

$isLab = $Channel -eq 'lab'
$serviceName = if ($isLab) { 'ActiumNodeSupervisorLab' } else { 'ActiumNodeSupervisor' }
$rootName = if ($isLab) { 'NodeManagerLab' } else { 'NodeManager' }
$root = Join-Path $env:ProgramData "Actium\$rootName"
$configDir = Join-Path $root 'config'
$stateDir = Join-Path $root 'state'
$nodesRoot = Join-Path $root 'nodes'
$fabricsRoot = Join-Path $root 'fabrics'
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

& $binaryPath --self-test
if ($LASTEXITCODE -ne 0) { throw 'El self-test del Supervisor fallo.' }
& $binaryPath --verify-payload $payloadPath
if ($LASTEXITCODE -ne 0) { throw 'El payload schema 3 fue rechazado.' }

if (-not (Get-LocalGroup -Name $operatorGroup -ErrorAction SilentlyContinue)) {
    New-LocalGroup -Name $operatorGroup -Description 'Operadores locales de Actium Node Manager' | Out-Null
}
$group = Get-LocalGroup -Name $operatorGroup
$groupSid = $group.SID.Value
$pipeSddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;$groupSid)"

foreach ($directory in @($configDir, $stateDir, $nodesRoot, $fabricsRoot, $binaryDir, (Join-Path $root 'logs'))) {
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
    $marker | ConvertTo-Json | Set-Content -LiteralPath $markerPath -Encoding utf8NoBOM
}

if (-not (Test-Path -LiteralPath $keyPath -PathType Leaf)) {
    $bytes = [byte[]]::new(48)
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    [IO.File]::WriteAllText($keyPath, [Convert]::ToBase64String($bytes), [Text.UTF8Encoding]::new($false))
}

$templatePath = Join-Path $PSScriptRoot 'supervisor.windows.toml.template'
$rootToml = $root.Replace('\', '/')
$fabricProject = if ($isLab) { 'actium-lab-fabric-01' } else { 'actium-node-fabric-01' }
$config = (Get-Content -LiteralPath $templatePath -Raw)
$config = $config.Replace('__CHANNEL__', $Channel)
$config = $config.Replace('__PIPE_NAME__', $serviceName)
$config = $config.Replace('__PIPE_SDDL__', $pipeSddl)
$config = $config.Replace('__SERVICE_NAME__', $serviceName)
$config = $config.Replace('__ROOT__', $rootToml)
$config = $config.Replace('__FABRIC_PROJECT__', $fabricProject)
[IO.File]::WriteAllText($configPath, $config, [Text.UTF8Encoding]::new($false))

# La UI necesita leer inventario y clave IPC, pero no modificar binario/configuracion del servicio.
& icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
& icacls.exe $nodesRoot /grant "*$groupSid`:(OI)(CI)RX" | Out-Null
& icacls.exe $fabricsRoot /grant "*$groupSid`:(OI)(CI)RX" | Out-Null
& icacls.exe $keyPath /grant "*$groupSid`:R" | Out-Null

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
$wasRunning = $service -and $service.Status -eq 'Running'
if ($service -and $service.Status -ne 'Stopped') {
    Stop-Service -Name $serviceName -Force
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
}

Copy-Item -LiteralPath $binaryPath -Destination $binaryNext -Force
if (Test-Path -LiteralPath $payloadNext) { Remove-Item -LiteralPath $payloadNext -Recurse -Force }
Copy-Item -LiteralPath $payloadPath -Destination $payloadNext -Recurse

if (Test-Path -LiteralPath $binaryPrevious) { Remove-Item -LiteralPath $binaryPrevious -Force }
if (Test-Path -LiteralPath $installedBinary) { Move-Item -LiteralPath $installedBinary -Destination $binaryPrevious }
Move-Item -LiteralPath $binaryNext -Destination $installedBinary
if (Test-Path -LiteralPath $payloadPrevious) { Remove-Item -LiteralPath $payloadPrevious -Recurse -Force }
if (Test-Path -LiteralPath $payloadTarget) { Move-Item -LiteralPath $payloadTarget -Destination $payloadPrevious }
Move-Item -LiteralPath $payloadNext -Destination $payloadTarget

$serviceCommand = '"{0}" --service --config "{1}"' -f $installedBinary, $configPath
if ($service) {
    & sc.exe config $serviceName binPath= $serviceCommand start= auto | Out-Null
} else {
    New-Service -Name $serviceName -BinaryPathName $serviceCommand -DisplayName "Actium Node Supervisor ($Channel)" -StartupType Automatic | Out-Null
}

try {
    & $installedBinary --config $configPath --check
    if ($LASTEXITCODE -ne 0) { throw 'El check owner-confirmed del Supervisor fallo.' }
} catch {
    if (Test-Path -LiteralPath $binaryPrevious) {
        Remove-Item -LiteralPath $installedBinary -Force -ErrorAction SilentlyContinue
        Move-Item -LiteralPath $binaryPrevious -Destination $installedBinary
    }
    if (Test-Path -LiteralPath $payloadPrevious) {
        Remove-Item -LiteralPath $payloadTarget -Recurse -Force -ErrorAction SilentlyContinue
        Move-Item -LiteralPath $payloadPrevious -Destination $payloadTarget
    }
    if ($wasRunning) { Start-Service -Name $serviceName }
    throw
}

if (-not $NoStart) {
    Start-Service -Name $serviceName
    (Get-Service -Name $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(20))
}

Write-Host "Actium Node Supervisor 0.5.5 ($Channel) instalado en $root"
Write-Host "Agregue operadores con: Add-LocalGroupMember -Group $operatorGroup -Member DOMINIO\\usuario"
