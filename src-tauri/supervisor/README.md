# Actium Node Supervisor 0.5.18

Servicio privilegiado de Actium Node Manager 0.7 para Debian 13 y Windows. El mismo `actium-node-core`, framing IPC v2 y autenticacion HMAC se transportan por socket Unix en Linux o named pipe con ACL en Windows.

El Supervisor es owner del journal SQLite, Docker/Compose, releases, reconciliacion explicita de red, Fabric y atestacion material Ed25519. La UI no recibe acceso al socket Docker ni rutas arbitrarias. Antes de iniciar, el servicio exige un marcador `root-ownership.json` que vincula canal, UUID y las dos raices autorizadas canonicalizadas.

## Canales y transicion

- Lab y Stable son paquetes y servicios paralelos durante el gate de fase 6.
- Lab usa `actium-lab-*` y Stable nuevo usa `actium-node-*`.
- Stable 0.7 no descubre, adopta ni migra `TelemetryNode`, `TelemetryNodes`, `telemetry-node` o `actium-center-01`.
- Stable 0.6.6 queda fuera de este runtime como rollback temporal; no existe selector de runtime Stable/Lab en la aplicacion nueva.
- `embedded_legacy` esta retirado de Actium Node Manager 0.7.
- El dominio y la UI identifican el candidato como `0.7.0-rc.2`; el bundle MSI usa `0.7.0-2` porque Windows Installer exige un prerelease numerico.

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
  -Channel lab
Add-LocalGroupMember -Group ActiumNodeOperators -Member "$env:USERDOMAIN\$env:USERNAME"
```

Stable candidato sustituye `-Channel lab` por `-Channel stable`. Las raices son:

El artefacto incluye el canal en el nombre y el build rechaza un `PAYLOAD.json` cuyo `productChannel` no coincida. Para el candidato Stable:

```powershell
$env:ACTIUM_PRODUCT_CHANNEL = 'stable'
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

Instalacion Lab:

```bash
sudo ./install-supervisor-debian.sh \
  --binary ../target/release/actium-node-supervisor \
  --payload ../resources/node \
  --channel lab
sudo usermod -aG actium-node-operators "$USER"
```

Gate:

```bash
systemctl status actium-node-supervisor-lab --no-pager
journalctl -u actium-node-supervisor-lab -n 100 --no-pager
stat -c '%A %U:%G %n' /run/actium/node-manager-lab.sock /etc/actium/node-manager-lab/ipc.key
/usr/lib/actium/node-manager-lab/actium-node-supervisor \
  --config /etc/actium/node-manager-lab/supervisor.toml --ping
```

El Supervisor nunca particiona ni formatea discos. Solo administra hijos directos de las raices owner-confirmed y no monta el socket Docker ni la identidad privada de atestacion dentro del Data Plane Agent.
