# Actium Node Supervisor 0.5.24

Servicio privilegiado de Actium Node Manager 0.7 para Debian 13 y Windows. El mismo `actium-node-core`, framing IPC v2 y autenticacion HMAC se transportan por socket Unix en Linux o named pipe con ACL en Windows.

El Supervisor es owner del journal SQLite, Docker/Compose, releases, reconciliacion explicita de red, Fabric y atestacion material Ed25519. La UI no recibe acceso al socket Docker ni rutas arbitrarias. Antes de iniciar, el servicio exige un marcador `root-ownership.json` que vincula canal, UUID y las dos raices autorizadas canonicalizadas.

## Canales y transicion

- Lab y Stable son paquetes y servicios paralelos durante el gate de fase 6.
- Lab usa `actium-lab-*` y Stable nuevo usa `actium-node-*`.
- Stable 0.7 no descubre, adopta ni migra `TelemetryNode`, `TelemetryNodes`, `telemetry-node` o `actium-center-01`.
- Stable 0.6.6 queda fuera de este runtime como rollback temporal; no existe selector de runtime Stable/Lab en la aplicacion nueva.
- `embedded_legacy` esta retirado de Actium Node Manager 0.7.
- El dominio y la UI identifican el candidato como `0.7.0-rc.4`; el bundle MSI usa `0.7.0-2` porque Windows Installer exige un prerelease numerico.

## Windows

Build:

```powershell
npm run prepare:payload
npm run supervisor:build:windows
```

Instalacion Lab como Administrador:

```powershell
.\install-supervisor-windows.ps1 `
  -Binary .\actium-node-supervisor.exe `
  -Payload .\payload `
  -Environment lab
Add-LocalGroupMember -Group ActiumNodeOperators -Member "$env:USERDOMAIN\$env:USERNAME"
```

Stable candidato sustituye `-Environment lab` por `-Environment stable`. `-Channel` se conserva como alias PowerShell de compatibilidad. LAB/STABLE son entornos de despliegue; DEV/RC/STABLE son canales de release. Las raices son:

El artefacto incluye el entorno en el nombre y el build rechaza un `PAYLOAD.json` cuyo `productChannel` (campo legacy que identifica el entorno) no coincida. Para el candidato Stable:

```powershell
$env:ACTIUM_DEPLOYMENT_ENVIRONMENT = 'stable'
$env:ACTIUM_DATA_PLANE_VERSION_FILE = 'VERSION.stable'
npm run prepare:payload
npm run supervisor:build:windows:stable
```

Los ZIP/TAR del Supervisor se publican bajo `src-tauri/target/release/bundle/supervisor/`; no se usa `installer/dist/` porque Vite limpia ese directorio en cada build.

Las raices son:

```text
C:\ProgramData\Actium\NodeManagerLab\
C:\ProgramData\Actium\NodeManager\
```

Named pipes:

```text
\\.\pipe\ActiumNodeSupervisorLab
\\.\pipe\ActiumNodeSupervisor
```

Gate:

```powershell
Get-Service ActiumNodeSupervisorLab
Get-LocalGroupMember ActiumNodeOperators
Get-Content "$env:ProgramData\Actium\NodeManagerLab\logs\supervisor.log" -Tail 100
& "$env:ProgramData\Actium\NodeManagerLab\bin\actium-node-supervisor.exe" `
  --config "$env:ProgramData\Actium\NodeManagerLab\config\supervisor.toml" --ping
```

La desinstalacion preserva datos por defecto. `-RemoveData` es una accion destructiva separada y explicita.

## Debian 13

Build:

```bash
cargo build --release --manifest-path src-tauri/Cargo.toml -p actium-node-supervisor
```

Deployment transaccional (el paquete instala assets; nunca activa un canal):

```bash
ENGINE="/usr/lib/Actium Node Manager/supervisor/actium-node-supervisor"
sudo "$ENGINE" deployment status --environment lab
sudo "$ENGINE" deployment capture-legacy --environment lab
sudo "$ENGINE" deployment stage --environment lab \
  --artifact ./actium-node-manager.deb \
  --release-manifest ./release-manifest.json \
  --expected-digest "sha256:<sha256-del-artefacto>"
# El stage devuelve deploymentId; sólo activar un journal READY_TO_ACTIVATE.
sudo "$ENGINE" deployment activate --environment lab --id "<deploymentId>"
sudo "$ENGINE" deployment verify --environment lab --id "<deploymentId>"
sudo "$ENGINE" deployment reconcile --environment lab --id "<deploymentId>"
```

Las unidades Debian arrancan mediante `service-launch`: usan el deployment
versionado cuando existe y sólo recurren al Supervisor previo cuando el canal
todavía no tiene puntero. El `preinst` conserva por canal el ejecutable
Supervisor que ya estaba instalado bajo
`/var/lib/actium/node-manager/legacy` y
`/var/lib/actium/node-manager-lab/legacy`, y también Authority bajo
`/var/lib/actium/authority-runtime/legacy`, antes de que `dpkg` retire las rutas
anteriores; no cambia punteros, inicia ni reinicia servicios. Así, un reinicio
posterior a un fallo de stage sigue arrancando la versión servida antes del
paquete, no el candidato recién desempaquetado.
El paquete contiene el candidato en `authority-package/`, separado del runtime
servido y del estado Authority durable.
La configuración de `dpkg` registra Authority como servicio habilitado para el
próximo arranque, pero no lo inicia ni reinicia; en un Host nuevo, el launcher
puede arrancar el binario del paquete como bootstrap mientras no exista un
puntero versionado o una copia legacy. Stable y Lab sólo se habilitan al activar
su deployment.

En un Host que todavía no tenga deployment del canal pero ya cuente con un
Authority servido y Trust Store válido, `deployment deploy` captura automáticamente
el baseline de Authority después del preflight y admite la primera activación del
Supervisor. Si se usa `stage` de forma aislada, primero se debe ejecutar
`deployment capture-authority-baseline`; así stage no crea ni cambia referencias
activas por su cuenta. Si falla la primera activación, rollback quita sólo el
puntero de ese candidato, deja el servicio del canal deshabilitado/inactivo y
verifica Authority y Trust Store antes de escribir `ROLLED_BACK_NO_ACTIVE_SUPERVISOR`.

La activación LAB no crea por sí sola un receipt de promoción. Después de
completar y guardar la evidencia del smoke funcional, escribir un informe con
el schema siguiente (los tres checks son obligatorios y deben ser `PASS`):

```json
{
  "schemaVersion": 1,
  "deploymentId": "<deploymentId>",
  "artifactDigest": "sha256:<sha256-del-artefacto>",
  "result": "PASS",
  "testSuite": "lab-functional-smoke-v1",
  "evidenceDigest": "sha256:<sha256-de-la-evidencia>",
  "checks": [
    "manager-ui-functional:PASS",
    "supervisor-channel-functional:PASS",
    "authority-trust-functional:PASS"
  ],
  "completedAt": "<timestamp-UTC>"
}
```

```bash
sudo "$ENGINE" deployment promote-lab --environment lab \
  --id "<deploymentId>" --smoke-report ./lab-smoke-report.json \
  --smoke-evidence ./lab-functional-smoke.log
sudo "$ENGINE" deployment stage --environment stable \
  --artifact ./actium-node-manager.deb \
  --release-manifest ./release-manifest.json \
  --expected-digest "sha256:<el-mismo-sha256-validado-en-lab>"
```

`promote-lab` vuelve a verificar el proceso servido y su activation receipt,
liga el informe/evidencia por SHA-256 y escribe un receipt inmutable que Stable
exige antes de aceptar ese digest.

Gate:

```bash
systemctl status actium-node-supervisor-lab --no-pager
journalctl -u actium-node-supervisor-lab -n 100 --no-pager
stat -c '%A %U:%G %n' /run/actium/node-manager-lab.sock /etc/actium/node-manager-lab/ipc.key
"$ENGINE" deployment status --environment lab
```

No usar `install-supervisor-debian.sh` para activar canales: es sólo un
forwarder compatible hacia `deployment`. La promoción a Stable requiere el
mismo `.deb` y digest con receipt `PROMOTABLE` emitido tras verificar LAB.

El Supervisor nunca particiona ni formatea discos. Solo administra hijos directos de las raices owner-confirmed y no monta el socket Docker ni la identidad privada de atestacion dentro del Data Plane Agent.
