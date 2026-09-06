# Packaging Linux

El artefacto oficial Linux es un `.deb` universal por versión, plataforma y
arquitectura. El bundle contiene el Manager y el Supervisor compilados con la
misma procedencia, además de configuración, scripts y unidades systemd.

El build no crea releases ni canales. La promoción posterior conserva los
SHA-256 del candidato (`PROMOTE, DON'T REBUILD`). El canal inicial del paquete
normal es `stable`; Lab sólo se instala mediante una acción explícita.

El paquete no contiene `PAYLOAD.json`, `resources/node` ni configuración de
cliente. El snapshot Aegis sigue siendo un artefacto de compatibilidad externo
y congelado.

## Recursos incluidos

`resources/supervisor` se recrea antes de cada build para impedir que un
artefacto de Windows o staging anterior contamine un paquete Linux. Sólo se
incluye el binario Linux del Supervisor y los recursos necesarios para su
instalación.

## Inspección reproducible

```bash
dpkg-deb -I actium-node-manager_<version>_amd64.deb
dpkg-deb -c actium-node-manager_<version>_amd64.deb
sha256sum actium-node-manager_<version>_amd64.deb
```

El contenido debe tener cero archivos `PAYLOAD.json` y la dependencia Debian
debe declarar Docker Engine, Compose v2, `systemd`, `openssl` e `iproute2`.
