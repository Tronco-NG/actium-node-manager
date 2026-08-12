[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$source = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$target = (Resolve-Path (Join-Path $PSScriptRoot 'src-tauri\resources\node')).Path

$directories = @('connectivity', 'contracts', 'coturn', 'docs', 'livekit', 'migrations', 'nats', 'observability', 'postgres', 'scripts')
foreach ($directory in $directories) {
    $sourceDirectory = Join-Path $source $directory
    $targetDirectory = Join-Path $target $directory
    New-Item -ItemType Directory -Force -Path $targetDirectory | Out-Null
    Copy-Item -Path (Join-Path $sourceDirectory '*') -Destination $targetDirectory -Recurse -Force
}

foreach ($service in @('agent', 'connector', 'telemetry', 'radio', 'site-core')) {
    $sourceService = Join-Path $source "services\$service"
    $targetService = Join-Path $target "services\$service"
    New-Item -ItemType Directory -Force -Path $targetService | Out-Null
    foreach ($name in @('.env.example', 'Dockerfile', 'docker-entrypoint.sh', 'README.md', 'package.json', 'package-lock.json', 'tsconfig.json')) {
        $candidate = Join-Path $sourceService $name
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { Copy-Item -LiteralPath $candidate -Destination (Join-Path $targetService $name) -Force }
    }
    foreach ($name in @('migrations', 'src', 'test')) {
        $candidate = Join-Path $sourceService $name
        if (Test-Path -LiteralPath $candidate -PathType Container) {
            $targetChild = Join-Path $targetService $name
            New-Item -ItemType Directory -Force -Path $targetChild | Out-Null
            Copy-Item -Path (Join-Path $candidate '*') -Destination $targetChild -Recurse -Force
        }
    }
}

foreach ($directory in @('keys', 'secrets')) {
    $targetDirectory = Join-Path $target $directory
    New-Item -ItemType Directory -Force -Path $targetDirectory | Out-Null
    foreach ($name in @('.gitignore', 'README.md')) {
        Copy-Item -LiteralPath (Join-Path $source "$directory\$name") -Destination (Join-Path $targetDirectory $name) -Force
    }
}

$files = @('.env.example', '.gitignore', 'VERSION', 'README.md', 'node.env.example', 'compose.yml', 'compose.build.yml', 'bootstrap.ps1', 'bootstrap.sh', 'install-node.ps1', 'install-node.sh', 'manage-node.ps1', 'manage-node.sh', 'verify-node.ps1', 'verify-node.sh')
foreach ($file in $files) { Copy-Item -LiteralPath (Join-Path $source $file) -Destination (Join-Path $target $file) -Force }

Write-Host "Recursos del instalador sincronizados desde $source" -ForegroundColor Green
