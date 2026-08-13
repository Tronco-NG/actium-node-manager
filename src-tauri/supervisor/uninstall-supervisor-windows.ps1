[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('lab', 'stable')][string]$Channel = 'lab',
    [switch]$RemoveData
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Ejecute este desinstalador desde PowerShell como Administrador.'
}

$isLab = $Channel -eq 'lab'
$serviceName = if ($isLab) { 'ActiumNodeSupervisorLab' } else { 'ActiumNodeSupervisor' }
$rootName = if ($isLab) { 'NodeManagerLab' } else { 'NodeManager' }
$root = Join-Path $env:ProgramData "Actium\$rootName"
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') { Stop-Service -Name $serviceName -Force }
    & sc.exe delete $serviceName | Out-Null
}
if ($RemoveData) {
    if ($PSCmdlet.ShouldProcess($root, 'Eliminar datos del canal Actium')) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
} else {
    Write-Host "Servicio retirado. Datos preservados en $root"
}
