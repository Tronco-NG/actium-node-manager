# Actium Node Supervisor 0.2.0

Servicio Linux privilegiado para el canal Lab de Actium Node Manager. Es dueño del socket Docker, del journal SQLite, de la promoción de releases y de la reconciliación explícita de red.

El Manager envía contratos HMAC tipados. El Supervisor crea nodos sólo como hijos directos de `/srv/actium-data/nodes`, crea el Fabric sólo dentro de `/srv/actium-data/fabrics`, usa exclusivamente su payload schema 3 verificado y limita el storage adicional a las raíces autorizadas. El Manager no entrega rutas de runtime ni recibe inspecciones Docker crudas.

## Build en Debian 13

```bash
cargo build --release --manifest-path src-tauri/Cargo.toml -p actium-node-supervisor
```

## Instalación

Desde este directorio:

```bash
sudo ./install-supervisor-debian.sh \
  --binary ../target/release/actium-node-supervisor \
  --payload ../resources/node
sudo usermod -aG actium-node-operators "$USER"
```

Desde el artefacto `.tar.gz` generado por `npm run supervisor:build:linux`:

```bash
tar -xzf actium-node-supervisor-0.2.0-linux-x86_64.tar.gz
cd actium-node-supervisor-0.2.0
./actium-node-supervisor --self-test
sudo ./install-supervisor-debian.sh --binary ./actium-node-supervisor --payload ./payload
```

Hay que cerrar y volver a abrir la sesión para recibir el grupo. La clave HMAC queda en `/etc/actium/node-manager/ipc.key` con `0640 root:actium-node-operators`; el socket se crea como `0660 root:actium-node-operators`.

Una reinstalación conserva `supervisor.toml`, publica la nueva plantilla como `supervisor.toml.dist` y mantiene el binario/payload anterior para rollback si falla `--check`.

## Gate manual

```bash
systemctl status actium-node-supervisor --no-pager
journalctl -u actium-node-supervisor -n 100 --no-pager
stat -c '%A %U:%G %n' /run/actium/node-manager.sock /etc/actium/node-manager/ipc.key
/usr/lib/actium/node-manager/actium-node-supervisor --config /etc/actium/node-manager/supervisor.toml --ping
```

Después de comprobar start/restart/update y recovery tras reboot, el usuario gráfico puede salir del grupo Docker:

```bash
sudo gpasswd -d "$USER" docker
```

No se particionan, formatean ni eliminan discos. El Supervisor rechaza rutas fuera de `authorized_nodes_root` y `authorized_fabrics_root`, nodos sin `managerChannel=lab` y proyectos Compose sin prefijo `actium-lab-`. El Fabric compartido mantiene un solo PostgreSQL, un solo NATS y una red externa interna por host; cada runtime unit conserva proyecto, recursos, secretos y health independientes.
