# Auditoría de resiliencia del runtime de nodos

**Fecha:** 2026-09-21
**Alcance:** VM de laboratorio `actium-lab-01` / Node Manager / Site Core
**Modo:** auditoría read-only; no se detuvieron contenedores ni servicios
**Severidad:** P1 — degradación severa de la VM por crash-loop controlado de forma insuficiente
**Estado:** causa raíz confirmada; mitigación y cambios estructurales pendientes

## 1. Resumen ejecutivo

La VM no sufrió un kernel panic, un OOM killer ni un disco lleno. Quedó degradada por un contenedor Site Core que reiniciaba indefinidamente porque sus contratos de delegación estaban vencidos.

La cadena observada fue:

```text
contrato firmado con offline_until vencido
        ↓
Site Core rechaza correctamente el contrato: JWTExpired
        ↓
proceso termina con exit=1
        ↓
Docker restartPolicy=unless-stopped lo vuelve a iniciar
        ↓
Supervisor y Docker ejecutan health checks repetidos
        ↓
load elevado + swap casi agotada + UI/SSH degradados
```

La seguridad criptográfica funcionó: el nodo no aceptó una delegación expirada. La resiliencia operativa falló: no hubo admisión previa, backoff, circuit breaker ni cuarentena después de miles de reinicios.

La mejora prioritaria no es aceptar contratos vencidos. Es convertir el rechazo esperado en un estado durable y operativo que detenga el loop, preserve evidencia y solicite renovación firmada.

## 2. Evidencia del incidente

| Señal | Evidencia observada | Interpretación |
|---|---|---|
| Plataforma | Debian 13, KVM/QEMU, kernel `6.12.101+deb13-amd64` | VM de laboratorio, no host físico |
| Boot | `2026-09-11 08:25`; sin reboot posterior en `last -x` | la VM no había reiniciado recientemente |
| Load | `42.36 / 64.59 / 40.91`, luego `13.10 / 50.55 / 37.84` | saturación y backlog de trabajo |
| Memoria | aproximadamente `2.5 GiB`; disponible inferior a `0.7 GiB` | margen muy pequeño para una estación con GUI, Docker y servicios |
| Swap | aproximadamente `1.3 GiB`, casi completamente usada | presión de memoria severa; no causa primaria por sí sola |
| Disco | `/` al `71%`; `/srv/actium-lab` al `7%` | no había full disk ni falta de inodes |
| Kernel | sin OOM killer, panic, lockup ni I/O error en el boot actual | descarta una falla de kernel como causa principal |
| Contenedor | `actium-node-actium-home-01-site-core-s-c66455ad-site-core` | workload afectado |
| Imagen | `actium/site-core:0.1.1` | artifact que ejecuta Site Core |
| Estado | `Restarting`, `exit=1`, `OOMKilled=false` | finalización lógica de la aplicación, no falta de memoria del cgroup |
| Reinicios | `restartCount=7290` durante la auditoría | crash-loop prolongado |
| Política | Docker `unless-stopped` | reinicio automático sin límite útil para este tipo de error |
| Error | `site_runtime_unavailable`, `JWTExpired`, `ERR_JWT_EXPIRED` | contrato de delegación rechazado por expiración |
| Validez | `offline_until=2026-09-16`; fecha de auditoría `2026-09-21` | el contrato llevaba varios días vencido |
| Health check | `wget: can't connect ... 127.0.0.1`; checks con timeout | el proceso no llega a servir antes de terminar |

## 3. Qué funcionó y qué falló

### Funcionó

- La validación de firma y claims rechazó un contrato vencido.
- El sistema no hizo bypass de `exp` ni de `offline_until`.
- `actium-authority.service`, ambos Supervisors y Center permanecieron activos.
- SSH y el guest agent siguieron respondiendo; la VM no estaba apagada.
- El diagnóstico read-only pudo correlacionar proceso, contenedor, imagen y causa.
- Node Manager ya dispone de provenance de build, health checks, activation receipt, LKG y estados fail-closed para Authority Lifecycle.

### Falló

- No hubo un preflight temporal antes de iniciar Site Core.
- El error `JWTExpired` no se promovió a un estado de runtime visible y durable.
- Docker siguió reiniciando un workload que no podía recuperarse sin un artifact nuevo.
- No hubo límite de reinicios, backoff suficiente ni cuarentena automática.
- La presión de recursos no generó una señal operacional prioritaria.
- La UI no protegió al operador de interpretar la VM como simplemente “caída”.
- Un reboot no habría resuelto la causa: al arrancar, Docker habría repetido el mismo loop.

## 4. Capacidades actuales relevantes

### Node Manager y Supervisor

- Supervisión de procesos y workloads Docker.
- Health checks y lectura de estado observado.
- Configuraciones separadas para Stable y Lab.
- Metadatos de build: `sourceCommit`, `buildId`, digest e `install_generation`.
- Contratos de autoridad con validación fail-closed.
- `SuccessorActivationV1` para Authority Lifecycle.
- Promoción atómica, LKG, receipt durable y rollback para Trust Bundle.
- Estados de lifecycle separados de release de software y de instalación.

### Runtime de Site Core

- Verificación criptográfica del contrato de delegación.
- Verificación de `exp` y ventana offline.
- Terminación explícita cuando el contrato no es válido.
- Health endpoint como señal de disponibilidad de la aplicación.

### Infraestructura

- Docker Compose y systemd.
- Límites de memoria por contenedor.
- Journald, logs JSON de Docker y eventos de Docker.
- Guest agent QEMU y acceso SSH para diagnóstico.

Estas capacidades son suficientes para detectar el incidente, pero no para contenerlo automáticamente.

## 5. Gaps estructurales

### G1 — Admisión temporal antes del arranque

El Supervisor debe validar, antes de crear o reiniciar un workload, la ventana temporal del contrato: `iat`, `nbf`, `exp`, `offline_until`, reloj local y autoridad/epoch. Un contrato ya vencido no debe llegar al ciclo de arranque.

### G2 — Circuit breaker por workload

Un proceso que falla con una causa no recuperable no puede reiniciarse indefinidamente. El estado debe pasar a `QUARANTINED` o `RECOVERY_REQUIRED` después de un umbral y persistir ese estado tras reboot.

### G3 — Backoff y clasificación de errores

`JWT_EXPIRED`, firma inválida, issuer incorrecto, dependencia ausente y crash de aplicación no son equivalentes. Cada causa debe tener política de retry distinta.

### G4 — Observabilidad operativa

El operador necesita ver:

- causa estable del bloqueo;
- cantidad de reinicios y ventana temporal;
- próxima expiración de credenciales;
- consumo de memoria/swap;
- acción requerida;
- último artifact y contrato correlacionados.

### G5 — Presupuesto de recursos de la VM

La combinación GUI + WebKit + Docker + Node Manager + Demiurge + Postgres + telemetry no tiene suficiente margen con `2.5 GiB`. El nodo debe declarar capacidad, reserva y umbral de presión antes de aceptar más workloads.

### G6 — Renovación antes de expiración

La renovación debe ser una operación explícita y firmada, con aviso anticipado. No debe depender de que el workload falle para descubrir que el contrato venció.

### G7 — Recuperación segura

La recuperación debe distinguir:

```text
RESTARTABLE_FAILURE
CONTRACT_EXPIRED
CONTRACT_INVALID
AUTHORITY_UNREACHABLE
RESOURCE_PRESSURE
QUARANTINED
```

Reiniciar o hacer reboot no debe ser la respuesta genérica.

## 6. Diseño recomendado para las próximas capacidades

### 6.1 Runtime Admission Guard

Introducir una primitiva reusable, por ejemplo `RuntimeAdmissionV1`, en el Supervisor:

```text
DISCOVERED
  → PROVENANCE_VALID
  → TEMPORAL_VALID
  → RESOURCE_ADMISSIBLE
  → DEPENDENCIES_READY
  → START_ALLOWED
```

Si falla una validación:

```text
START_BLOCKED
  → CONTRACT_EXPIRED | CONTRACT_INVALID | RESOURCE_PRESSURE | DEPENDENCY_UNAVAILABLE
```

El guard no modifica ni renueva secretos. Sólo valida metadata pública, claims y referencias seguras antes de iniciar.

### 6.2 Runtime Failure Receipt

Emitir un receipt durable por fallo no recuperable con:

- `runtimeUnitId`;
- deployment y node;
- artifact/digest;
- contract ID y authority epoch;
- `failureCode` normalizado;
- `firstObservedAt` y `lastObservedAt`;
- `restartCount` y ventana de retry;
- `resourceSnapshot` sin secretos;
- `nextAction`;
- resultado `QUARANTINED`, `RECOVERY_REQUIRED` o `RETRYING`.

### 6.3 Circuit breaker persistente

Política inicial sugerida para revisión de producto:

```text
1 fallo: retry con backoff corto
2-3 fallos: backoff creciente
fallo no recuperable confirmado: no retry automático
umbral de reinicios alcanzado: QUARANTINED
```

Los valores exactos deben ser configurables por capability/runtime class, no hardcodeados para Site Core.

### 6.4 Estado de validez temporal

Agregar estados operativos visibles:

```text
VALID
EXPIRING_SOON
EXPIRED
RENEWAL_REQUIRED
QUARANTINED
```

`EXPIRING_SOON` debe aparecer con horizonte configurable —por ejemplo 72 h y 24 h— y no esperar al primer crash.

### 6.5 Presupuesto y presión de recursos

Antes de habilitar una capability, el nodo debe evaluar:

- RAM disponible;
- swap disponible y tasa de swap-in/swap-out;
- carga por CPU;
- espacio e inodes;
- límite de procesos;
- límite Docker/cgroup;
- costo de la GUI local;
- workloads ya admitidos.

Estados sugeridos:

```text
RESOURCE_HEALTHY
RESOURCE_PRESSURE
RESOURCE_EXHAUSTED
```

`RESOURCE_PRESSURE` debe impedir nuevas activaciones no esenciales y notificar al operador.

### 6.6 Separar restart policy de recovery policy

Docker `unless-stopped` es un mecanismo de disponibilidad, no una política de recuperación semántica. La política correcta debe vivir en Supervisor y decidir si el error es reintentable.

El Supervisor debe poder solicitar una cuarentena sin destruir evidencia ni borrar el workload. La cuarentena debe ser reversible mediante una acción explícita y verificable.

## 7. Plan priorizado

### P0 — evitar otra degradación de VM

1. Preflight temporal antes de cada start/restart.
2. Normalizar `JWT_EXPIRED` y `OFFLINE_WINDOW_EXPIRED`.
3. Circuit breaker y backoff por `runtimeUnitId`.
4. Estado durable `QUARANTINED`.
5. Alertas de expiración a 72 h/24 h.
6. Métricas de restart rate, swap pressure y load.
7. UI con acción concreta: “renovar contrato firmado”, no “reiniciar”.

### P1 — recuperación operativa

1. Renewal workflow firmado y separado de deploy.
2. Runtime Failure Receipt y correlación con artifact.
3. Comando read-only de diagnóstico reproducible.
4. Comando de recovery con confirmación de operador.
5. Validación de clock/NTP y tolerancia explícita de skew.
6. Test de reboot con contrato válido, expirado y próximo a expirar.

### P2 — escala de nodos

1. Capability admission por presupuesto de recursos.
2. Health/readiness agregados por node, runtime unit y authority.
3. Fleet policy para expiración y renovación.
4. Mantenimiento coordinado con ventanas de actualización.
5. Reporte de capacidad antes de Host convergence.

## 8. Runbook de diagnóstico seguro

### 8.1 Confirmar que la VM está viva

```bash
hostname
date -Is
uptime
cat /proc/loadavg
free -h
cat /proc/swaps
df -hT
systemctl is-system-running
```

### 8.2 Clasificar la falla

```bash
journalctl -k -b --no-pager | grep -iE 'oom|panic|lockup|I/O error'
docker ps --all --no-trunc
docker ps --filter status=restarting
docker inspect <container> --format 'status={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} restart={{.RestartCount}}'
docker logs --tail 100 <container>
```

No exponer variables de entorno, tokens, claves, JWT completos ni archivos de secretos.

### 8.3 Si el error es de contrato vencido

1. No ejecutar reboot a ciegas.
2. No desactivar verificación de firma o expiración.
3. Preservar logs, `restartCount`, imagen, digest y release.
4. Autorizar una mitigación acotada del workload crash-loop.
5. Obtener un contrato firmado nuevo mediante el flujo de autoridad correspondiente.
6. Verificar claims, issuer, audience, epoch, digest y ventana temporal.
7. Instalar de forma controlada.
8. Liberar la cuarentena explícitamente.
9. Confirmar estabilidad durante una ventana sostenida.
10. Recién después operar Center, Host convergence o nuevas capabilities.

## 9. Matriz mínima de pruebas futuras

| Caso | Resultado esperado |
|---|---|
| Contrato válido | workload inicia y queda `RUNNING` |
| Contrato expira antes del start | `START_BLOCKED`, sin loop Docker |
| Contrato expira durante ejecución | drain/quarantine controlado, receipt durable |
| Firma inválida | fail-closed, sin retry indefinido |
| Authority unreachable | retry acotado y estado explícito |
| Clock adelantado | `CLOCK_SKEW_DETECTED`, no bypass |
| RAM baja/swap alta | `RESOURCE_PRESSURE`, no nuevas activaciones |
| Proceso crasha repetidamente | circuit breaker y `QUARANTINED` |
| Reboot con estado quarantined | cuarentena persiste; no vuelve el loop |
| Renovación firmada válida | recovery explícito y receipt nuevo |
| Supervisor reinicia | estado, conteos y razón se conservan |
| Docker daemon reinicia | no se pierde la política semántica del Supervisor |

## 10. Criterios de aceptación

La mejora se considera completa cuando:

- un contrato expirado nunca produce miles de reinicios;
- la VM conserva memoria y swap dentro de umbrales definidos;
- el operador ve la causa exacta y la acción autorizada;
- el estado de cuarentena sobrevive reboot y restart de Docker;
- la renovación no requiere bypass criptográfico;
- existe provenance correlacionable entre node, runtime, artifact y contrato;
- los receipts permiten reconstruir el incidente sin leer secretos;
- los tests cubren expiración, clock skew, presión de recursos y crash-loop;
- Host convergence sólo se habilita después de readiness real del runtime.

## 11. Decisiones pendientes

Estas decisiones requieren revisión de arquitectura/producto antes de implementar:

1. Umbral exacto de reinicios y ventana de backoff por clase de runtime.
2. Quién autoriza la liberación de una cuarentena.
3. Horizonte de alertas de expiración.
4. Presupuesto mínimo de RAM/swap para la VM de laboratorio.
5. Si la GUI local debe operar en una VM separada del runtime de nodos.
6. Política de renovación online/offline por tipo de contrato.
7. Retención de Runtime Failure Receipts y logs de crash-loop.

## 12. Dictamen

```text
INCIDENT_CAUSE = EXPIRED_SIGNED_SITE_CORE_DELEGATION
SECURITY_VALIDATION = PASS
RUNTIME_RECOVERY_POLICY = FAIL
RESOURCE_HEADROOM = FAIL
KERNEL_FAILURE = NOT_CONFIRMED
OOM = NOT_OBSERVED
DISK_FULL = NOT_OBSERVED
VM_ALIVE = YES
NODE_RUNTIME_RESILIENCE = BLOCKED_PENDING_P0
R1 = NO-GO
CONNECTIVITY_V1_CLOSED = NO-GO
```

La lección principal es operacional: **fail-closed debe ir acompañado de fail-contained**. Rechazar un contrato inválido protege la autoridad; aislar el workload que no puede recuperarse protege la VM y permite que el operador recupere el sistema.
