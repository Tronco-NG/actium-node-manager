import { invoke } from "@tauri-apps/api/core";
import "./styles.css";

type SystemInfo = {
  platform: string;
  architecture: string;
  defaultInstallDir: string;
  dockerCli: boolean;
  dockerDaemon: boolean;
  composeV2: boolean;
  dependencyInstallSupported: boolean;
  dependencyMessage: string;
  payloadVersion: string;
  suggestedPublicBaseUrl: string;
  managedNodesDir: string;
};

type InstallationState = {
  installed: boolean;
  operational: boolean;
  managed: boolean;
  version?: string;
  profiles: string[];
  config: Record<string, string>;
  markerPath: string;
  status?: string;
  deploymentId?: string;
  deploymentCode?: string;
  installationId?: string;
  recoverableIncompletePreparation: boolean;
  lastError?: string;
};

type ActionResult = {
  ok: boolean;
  message: string;
  output: string;
  installedProfiles: string[];
};

type ManagedNode = {
  key: string;
  installDir: string;
  displayName: string;
  projectName?: string;
  deploymentId?: string;
  deploymentCode?: string;
  installationId?: string;
  version?: string;
  profiles: string[];
  status: string;
  operational: boolean;
  recoverable: boolean;
  archived: boolean;
  canManage: boolean;
  lastError?: string;
  totalServices: number;
  runningServices: number;
  startingServices: number;
  unhealthyServices: number;
  connectivityConfigured: boolean;
  connectivityNodeRole?: string;
  connectivityNodePriority?: number;
  connectivityPullLimit?: number;
  connectivityDirectDataPlaneFallbackEnabled: boolean;
  connectivitySupabaseFallbackEnabled: boolean;
  connectivityFallbackOrder: string[];
  connectivityEdgeEnrollmentTokenConfigured: boolean;
  connectivityInternalRelayTokenConfigured: boolean;
};

type NodeAuditService = {
  workload: string;
  containerName: string;
  state: string;
  health: string;
};

type NodeTelemetryAudit = {
  organizationId: string;
  terminalId: string;
  terminalLabel?: string | null;
  bindingEpoch?: number | null;
  sequence?: number | null;
  fixAt?: string | null;
  ingestedAt?: string | null;
  projectedAt?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  accuracy?: number | null;
  speed?: number | null;
  heading?: number | null;
  continuityStatus?: "live" | "degraded" | "stale" | null;
  queueLagSeconds?: number | null;
  heartbeatAt?: string | null;
  presenceStatus?: "online" | "degraded" | "offline" | null;
  appState?: string | null;
  batteryLevel?: number | null;
  queueDepth?: number | null;
  lastBatchId?: string | null;
  lastBatchReceivedAt?: string | null;
  lastBatchProcessedAt?: string | null;
  lastBatchStatus?: "processing" | "processed" | "failed" | null;
  lastBatchErrorCode?: string | null;
  lastBatchPointCount?: number | null;
  dvrFirstPointAt?: string | null;
  dvrLastPointAt?: string | null;
  dvrPoints24h: number;
  dvrSessionId?: string | null;
};

type NodeAuditSnapshot = {
  generatedAt: string;
  projectName: string;
  services: NodeAuditService[];
  databaseOk: boolean;
  databaseError?: string | null;
  telemetry: {
    terminals: NodeTelemetryAudit[];
    unresolvedDeadLetters: number;
    recentDeadLetters: Array<{
      stream: string;
      subject: string;
      category: string;
      reason: string;
      failedAt: string;
    }>;
  };
};

type InstallationTarget = {
  installDir: string;
  matchedExisting: boolean;
  installation: InstallationState;
};

type Profile = {
  id: string;
  title: string;
  scope: string;
  description: string;
  ports: string;
};

type NetworkMode = "local_only" | "trusted_lan" | "stable_vpn";

type BootstrapValidation = {
  valid: boolean;
  deploymentId: string;
  deploymentCode: string;
  deploymentName: string;
  organizationId?: string;
  generation: number;
  checksum: string;
  expiresAtUnixSeconds: number;
  profiles: string[];
  controlEndpoint: string;
  signingKeyRef: string;
  installerMinVersion: string;
  connectivityPolicy?: {
    edgeControlUrl: string;
    nodeRole: "primary" | "replica";
    nodePriority: number;
    pullLimit: number;
    directDataPlaneFallbackEnabled: boolean;
    supabaseFallbackEnabled: boolean;
    fallbackOrder: Array<"direct_data_plane" | "supabase">;
  };
};

type NetworkPortPlan = {
  telemetryPort: number;
  radioControlPort: number;
  prometheusPort: number;
  grafanaPort: number;
  turnPort: number;
  turnTlsPort: number;
  turnMinPort: number;
  turnMaxPort: number;
  livekitHttpPort: number;
  livekitRtcTcpPort: number;
  livekitUdpMinPort: number;
  livekitUdpMaxPort: number;
};

const profiles: Profile[] = [
  { id: "telemetry", title: "GPS + DVR", scope: "Telemetry", description: "Ingesta por lotes, histórico append-only, proyección actual O(1) y heartbeats independientes.", ports: "8090/TCP" },
  { id: "radio-control", title: "HT Radio Control", scope: "PTT", description: "Presencia, señalización, autorización, floor leases y coordinación de motores PTT.", ports: "8100/TCP" },
  { id: "radio-saf", title: "Store & Forward", scope: "S&F", description: "Audio diferido y metadatos durables con almacenamiento S3-compatible local.", ports: "9000-9001/TCP local" },
  { id: "radio-turn", title: "TURN para Mesh", scope: "WebRTC", description: "Relay coturn para WebRTC Mesh cuando la conectividad P2P directa no es posible.", ports: "3478 TCP/UDP + rango UDP" },
  { id: "radio-livekit", title: "LiveKit SFU", scope: "Premium", description: "Motor SFU independiente para canales configurados expresamente como LiveKit.", ports: "7880-7881/TCP + 50000-50100/UDP" },
  { id: "observability", title: "Observabilidad", scope: "SRE", description: "Prometheus y Grafana locales para salud, latencia, colas y consumo por stream.", ports: "9090 y 3001/TCP local" },
  { id: "connectivity", title: "Connectivity Edge", scope: "Continuidad", description: "Conector saliente con cursor durable, fencing y replica Edge a Node sin exponer Docker.", ports: "HTTPS saliente" },
];

let system: SystemInfo;
let installation: InstallationState = {
  installed: false,
  operational: false,
  managed: false,
  profiles: [],
  config: {},
  markerPath: "",
  recoverableIncompletePreparation: false,
};
let bootstrapJws = "";
let bootstrapValidation: BootstrapValidation | null = null;
let activeStep = 0;
let validatedSteps = [false, false, false, false, false];
let busy = false;
let viewMode: "manager" | "wizard" | "configuration" | "audit" = "wizard";
let managedNodes: ManagedNode[] = [];
let wizardTargetPinned = false;
let configurationNodeIndex: number | null = null;
let auditNodeIndex: number | null = null;
let auditSnapshot: NodeAuditSnapshot | null = null;
let auditError: string | null = null;
let auditTab: "gps" | "dvr" = "gps";
let auditRefreshTimer: number | null = null;
let auditRefreshInProgress = false;
let managerResult: { message: string; output: string; error: boolean } | null = null;
let networkConfigurationDeferred = false;
let trustedLanSyncInProgress = false;
const trustedLanSyncAttempts = new Map<string, string>();
let autoAssignedPortsDeploymentId: string | null = null;

const app = document.querySelector<HTMLDivElement>("#app")!;
if (!app) throw new Error("No se encontro el contenedor principal.");

function escapeHtml(value: string): string {
  return value.replace(/[&<>'"]/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "'": "&#39;",
    '"': "&quot;",
  })[character] ?? character);
}

function statusChip(ok: boolean, okText: string, badText: string): string {
  return `<span class="status-chip ${ok ? "ok" : "bad"}"><i></i>${escapeHtml(ok ? okText : badText)}</span>`;
}

function hasOperationalInstallation(): boolean {
  return installation.operational;
}

function validNetworkMode(value: string | undefined): value is NetworkMode {
  return value === "local_only" || value === "trusted_lan" || value === "stable_vpn";
}

function configuredNetworkMode(): NetworkMode {
  const configured = installation.config.DATA_PLANE_NETWORK_MODE;
  if (validNetworkMode(configured)) return configured;
  const baseUrl = installation.config.DATA_PLANE_PUBLIC_BASE_URL ?? "";
  const bindAddress = installation.config.DATA_PLANE_BIND_ADDRESS ?? "";
  return bindAddress === "127.0.0.1" || /^https?:\/\/(?:127\.0\.0\.1|localhost)(?::|\/|$)/i.test(baseUrl)
    ? "local_only"
    : "trusted_lan";
}

function networkModeOptions(selected: NetworkMode): string {
  return [
    ["local_only", "Sólo este equipo"],
    ["trusted_lan", "LAN de confianza"],
    ["stable_vpn", "VPN estable"],
  ].map(([value, label]) => `<option value="${value}" ${selected === value ? "selected" : ""}>${label}</option>`).join("");
}

function networkModeDescription(mode: NetworkMode): string {
  if (mode === "local_only") return "Publica únicamente por loopback. Funciona al mover el equipo y no expone servicios a la red.";
  if (mode === "trusted_lan") return "Usa la ruta activa. Con el Manager abierto, detecta cambios cada 15 s y reaplica sólo los endpoints derivados; DNS/proxy personalizados se conservan.";
  return "Conserva una URL/IP de VPN estable aunque cambie la Wi-Fi o el proveedor de acceso.";
}

function fallbackOrderOptions(selected: string): string {
  return [
    ["", "Sin fallback adicional"],
    ["direct_data_plane", "Sólo Data Plane directo"],
    ["supabase", "Sólo Supabase"],
    ["direct_data_plane,supabase", "Data Plane directo → Supabase"],
    ["supabase,direct_data_plane", "Supabase → Data Plane directo"],
  ].map(([value, label]) => `<option value="${value}" ${selected === value ? "selected" : ""}>${label}</option>`).join("");
}

function synchronizeFallbackOrder(prefix: "" | "config-"): void {
  const direct = input(`${prefix}connectivity-direct-data-plane-fallback-enabled`).checked;
  const supabase = input(`${prefix}connectivity-supabase-fallback-enabled`).checked;
  const select = document.querySelector<HTMLSelectElement>(`#${prefix}connectivity-fallback-order`);
  if (!select) return;
  if (direct && supabase) {
    if (!["direct_data_plane,supabase", "supabase,direct_data_plane"].includes(select.value)) {
      select.value = "direct_data_plane,supabase";
    }
    select.disabled = false;
  } else {
    select.value = direct ? "direct_data_plane" : supabase ? "supabase" : "";
    select.disabled = true;
  }
}

function hasDeploymentConflict(): boolean {
  return Boolean(
    installation.recoverableIncompletePreparation
      && installation.deploymentId
      && bootstrapValidation?.deploymentId
      && installation.deploymentId !== bootstrapValidation.deploymentId,
  );
}

function profileCards(): string {
  return profiles.map((profile) => {
    const installed = hasOperationalInstallation() && installation.profiles.includes(profile.id);
    const authorized = installed || bootstrapValidation?.profiles.includes(profile.id) === true;
    return `
      <label class="profile-card ${installed ? "installed" : ""} ${authorized ? "" : "unauthorized"}">
        <input type="checkbox" name="profiles" value="${profile.id}" ${installed ? "checked disabled" : authorized ? "" : "disabled"} />
        <span class="profile-check">✓</span>
        <span class="profile-copy">
          <span class="profile-kicker">${escapeHtml(profile.scope)}${installed ? " · instalado" : authorized ? "" : " · no autorizado"}</span>
          <strong>${escapeHtml(profile.title)}</strong>
          <small>${escapeHtml(profile.description)}</small>
          <code>${escapeHtml(profile.ports)}</code>
        </span>
      </label>`;
  }).join("");
}

const actionLabels: Record<string, string> = {
  status: "Estado",
  verify: "Verificar",
  start: "Iniciar",
  stop: "Detener",
  restart: "Reiniciar",
  update: "Actualizar",
  logs: "Registros",
};

function managerNodeState(node: ManagedNode): { label: string; tone: string } {
  if (node.archived) return { label: "Archivado recuperable", tone: "warning" };
  if (node.recoverable) return { label: `Preparación ${node.status}`, tone: "warning" };
  if (!node.operational) return { label: node.status === "missing" ? "Ruta no disponible" : node.status, tone: "bad" };
  if (node.unhealthyServices > 0) return { label: "Servicios degradados", tone: "warning" };
  if (node.startingServices > 0) return { label: "Servicios iniciando", tone: "neutral" };
  if (node.runningServices > 0 && node.runningServices === node.totalServices) return { label: "En ejecución", tone: "ok" };
  if (node.runningServices > 0) return { label: "Ejecución parcial", tone: "warning" };
  return { label: "Detenido", tone: "neutral" };
}

function renderManager(): void {
  const operational = managedNodes.filter((node) => node.operational && !node.archived).length;
  const recoverable = managedNodes.filter((node) => node.recoverable || node.archived).length;
  app.innerHTML = `
    <header class="topbar">
      <div class="brand-mark">A</div>
      <div>
        <span class="eyebrow">ACTIUM CONTROL PLANE</span>
        <h1>Telemetry Node Manager</h1>
      </div>
      <div class="version-pill">manager ${escapeHtml(system.payloadVersion)}</div>
    </header>
    <main class="manager-shell">
      <section class="manager-header">
        <div>
          <span class="eyebrow">GESTIÓN LOCAL PERSISTENTE</span>
          <h2>Nodos de este equipo</h2>
          <p>El inventario se reconstruye desde el registro local, los marcadores de instalación y los proyectos Docker Compose. Reiniciar la aplicación no pierde los nodos administrados.</p>
        </div>
        <div class="button-row">
          <button id="refresh-nodes" class="secondary">Actualizar estado</button>
          <button id="add-node" class="primary">Agregar nodo</button>
        </div>
      </section>
      <section class="manager-metrics">
        <article><span>Administrables</span><strong>${operational}</strong></article>
        <article><span>Recuperables</span><strong>${recoverable}</strong></article>
        <article><span>Docker</span><strong>${system.dockerDaemon ? "Operativo" : "No disponible"}</strong></article>
      </section>
      <section class="node-list">
        ${managedNodes.length === 0 ? `
          <div class="empty-manager">
            <strong>No se detectaron nodos todavía</strong>
            <span>Importe un paquete .adpe para registrar el primero.</span>
          </div>` : managedNodes.map((node, index) => {
            const state = managerNodeState(node);
            const serviceSummary = node.totalServices > 0
              ? `${node.runningServices}/${node.totalServices} servicios en ejecución`
              : node.operational ? "Sin contenedores activos" : "Sin servicios operativos";
            return `
              <article class="node-card ${node.archived ? "archived" : ""}">
                <div class="node-card-head">
                  <div>
                    <span class="eyebrow">${escapeHtml(node.deploymentCode ?? node.projectName ?? "IDENTIDAD RECUPERABLE")}</span>
                    <h3>${escapeHtml(node.displayName)}</h3>
                  </div>
                  <span class="manager-status ${state.tone}">${escapeHtml(state.label)}</span>
                </div>
                <div class="node-meta">
                  <span><strong>${escapeHtml(node.version ?? "legacy")}</strong> versión</span>
                  <span><strong>${escapeHtml(serviceSummary)}</strong> Docker</span>
                  <span><strong>${escapeHtml(node.profiles.join(", ") || "sin perfiles")}</strong> perfiles</span>
                </div>
                ${node.profiles.includes("connectivity") ? `<div class="node-meta connectivity-summary">
                  <span><strong>${node.connectivityConfigured ? "Configurado" : "Pendiente"}</strong> Connectivity Edge</span>
                  <span><strong>${escapeHtml(node.connectivityNodeRole ?? "replica")} · prioridad ${node.connectivityNodePriority ?? 100} · lote ${node.connectivityPullLimit ?? 25}</strong> recuperación</span>
                  <span><strong>${escapeHtml(node.connectivityFallbackOrder.join(" → ") || "sin fallback externo")}</strong> fallbacks</span>
                </div>` : ""}
                <code class="node-path">${escapeHtml(node.installDir)}</code>
                ${node.lastError ? `<div class="node-error">Último error: ${escapeHtml(node.lastError)}</div>` : ""}
                <div class="node-actions">
                  ${node.canManage ? ["status", "verify", "start", "stop", "restart", "update", "logs"]
                    .map((action) => `<button class="secondary small manager-action" data-node-index="${index}" data-action="${action}">${actionLabels[action]}</button>`)
                    .join("") : ""}
                  ${node.operational && !node.archived && node.profiles.includes("telemetry") ? `<button class="secondary small audit-node" data-node-index="${index}">Auditoría</button>` : ""}
                  ${node.operational && !node.archived ? `<button class="secondary small configure-node" data-node-index="${index}">Configurar</button>` : ""}
                  ${node.operational && node.archived
                    ? `<button class="primary small promote-node" data-node-index="${index}">Promover nodo</button>`
                    : `<button class="secondary small open-wizard" data-node-index="${index}">${node.operational ? "Ampliar con .adpe" : "Recuperar con .adpe"}</button>`}
                </div>
              </article>`;
          }).join("")}
      </section>
      <section id="manager-result" class="result ${managerResult ? managerResult.error ? "error" : "success" : "empty"}">
        <strong>${escapeHtml(managerResult?.message ?? "Registro del gestor")}</strong>
        <pre>${escapeHtml(managerResult?.output || "Seleccione una operación para ver su resultado.")}</pre>
      </section>
    </main>
    <div id="busy-overlay" class="busy-overlay ${busy ? "visible" : ""}"><div class="spinner"></div><strong>Procesando…</strong><small>No cierre el gestor.</small></div>
  `;
  bindManagerEvents();
}

function auditTimestamp(value?: string | null): string {
  if (!value) return "sin datos";
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return value;
  return new Date(parsed).toLocaleString();
}

function auditAge(value?: string | null): string {
  if (!value) return "nunca";
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return "fecha inválida";
  const seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1_000));
  if (seconds < 60) return `hace ${seconds}s`;
  if (seconds < 3_600) return `hace ${Math.floor(seconds / 60)}m`;
  if (seconds < 86_400) return `hace ${Math.floor(seconds / 3_600)}h`;
  return `hace ${Math.floor(seconds / 86_400)}d`;
}

function auditServiceHealthy(service: NodeAuditService | undefined): boolean {
  return service?.state === "running" && (service.health === "healthy" || service.health === "running");
}

function auditStage(label: string, value: string, state: "ok" | "warning" | "bad" | "neutral", detail: string): string {
  return `<article class="audit-stage ${state}">
    <span>${escapeHtml(label)}</span>
    <strong>${escapeHtml(value)}</strong>
    <small>${escapeHtml(detail)}</small>
  </article>`;
}

function renderGpsAuditTerminal(terminal: NodeTelemetryAudit, gatewayHealthy: boolean, projectorHealthy: boolean): string {
  const batchState = terminal.lastBatchStatus === "processed"
    ? "ok"
    : terminal.lastBatchStatus === "processing"
      ? "warning"
      : terminal.lastBatchStatus === "failed"
        ? "bad"
        : "neutral";
  const presenceState = terminal.presenceStatus === "online"
    ? "ok"
    : terminal.presenceStatus === "degraded"
      ? "warning"
      : terminal.presenceStatus === "offline"
        ? "bad"
        : "neutral";
  const projectionState = terminal.fixAt
    ? terminal.continuityStatus === "live"
      ? "ok"
      : terminal.continuityStatus === "degraded"
        ? "warning"
        : "bad"
    : "neutral";
  const readState = gatewayHealthy && terminal.projectedAt ? "ok" : gatewayHealthy ? "warning" : "bad";
  const coordinates = Number.isFinite(terminal.latitude) && Number.isFinite(terminal.longitude)
    ? `${Number(terminal.latitude).toFixed(6)}, ${Number(terminal.longitude).toFixed(6)}`
    : "sin posición";
  return `<article class="audit-terminal-card">
    <div class="audit-terminal-head">
      <div>
        <span class="eyebrow">${escapeHtml(terminal.organizationId)}</span>
        <h3>${escapeHtml(terminal.terminalLabel || "Nombre no informado")}</h3>
        <div class="audit-terminal-identity"><span>UUID</span><code>${escapeHtml(terminal.terminalId)}</code></div>
      </div>
      <span class="manager-status ${presenceState}">${escapeHtml(terminal.presenceStatus || "sin heartbeat")}</span>
    </div>
    <div class="audit-pipeline">
      ${auditStage(
        "1 · Terminal / heartbeat",
        terminal.presenceStatus || "sin señal",
        presenceState,
        `${auditAge(terminal.heartbeatAt)} · ${terminal.appState || "estado desconocido"} · cola ${terminal.queueDepth ?? 0}`,
      )}
      ${auditStage(
        "2 · Ingress / lote",
        terminal.lastBatchStatus || "sin lotes",
        batchState,
        terminal.lastBatchReceivedAt
          ? `recibido ${auditAge(terminal.lastBatchReceivedAt)} · ${terminal.lastBatchPointCount ?? 0} puntos${terminal.lastBatchErrorCode ? ` · ${terminal.lastBatchErrorCode}` : ""}`
          : "El servidor todavía no recibió un lote de esta terminal.",
      )}
      ${auditStage(
        "3 · Broker / proyector",
        projectorHealthy ? terminal.projectedAt ? "proyectado" : "sin proyección" : "servicio no saludable",
        projectorHealthy ? projectionState : "bad",
        terminal.projectedAt
          ? `proyección ${auditAge(terminal.projectedAt)} · captura→proyección ${terminal.queueLagSeconds ?? 0}s`
          : "No existe terminal_location_current para esta identidad.",
      )}
      ${auditStage(
        "4 · Lectura HybridMap",
        gatewayHealthy && terminal.projectedAt ? "disponible" : "no disponible",
        readState,
        `${coordinates} · posición capturada ${auditAge(terminal.fixAt)} · precisión ${terminal.accuracy ?? "s/d"}m`,
      )}
    </div>
  </article>`;
}

function renderDvrAuditTerminal(terminal: NodeTelemetryAudit, gatewayHealthy: boolean): string {
  const pointCount = Number(terminal.dvrPoints24h || 0);
  const dvrState = pointCount > 0 ? "ok" : terminal.lastBatchStatus === "failed" ? "bad" : "warning";
  return `<article class="audit-terminal-card">
    <div class="audit-terminal-head">
      <div>
        <span class="eyebrow">${escapeHtml(terminal.organizationId)}</span>
        <h3>${escapeHtml(terminal.terminalLabel || "Nombre no informado")}</h3>
        <div class="audit-terminal-identity"><span>UUID</span><code>${escapeHtml(terminal.terminalId)}</code></div>
      </div>
      <span class="manager-status ${dvrState}">${pointCount} puntos / 24h</span>
    </div>
    <div class="audit-pipeline">
      ${auditStage(
        "1 · Registro append-only",
        pointCount > 0 ? "grabando" : "sin puntos",
        dvrState,
        `Primero ${auditTimestamp(terminal.dvrFirstPointAt)} · último ${auditAge(terminal.dvrLastPointAt)}`,
      )}
      ${auditStage(
        "2 · Sesión DVR",
        terminal.dvrSessionId || "sin id de sesión",
        terminal.dvrSessionId ? "ok" : pointCount > 0 ? "warning" : "neutral",
        terminal.dvrSessionId
          ? "La terminal está etiquetando el recorrido para reproducción."
          : "Los puntos existen, pero no publican dvrSessionId.",
      )}
      ${auditStage(
        "3 · Último punto",
        terminal.dvrLastPointAt ? auditAge(terminal.dvrLastPointAt) : "nunca",
        terminal.dvrLastPointAt ? "ok" : "neutral",
        terminal.dvrLastPointAt ? auditTimestamp(terminal.dvrLastPointAt) : "No existe histórico en la ventana auditada.",
      )}
      ${auditStage(
        "4 · Ruta de lectura",
        gatewayHealthy && pointCount > 0 ? "consultable" : "pendiente",
        gatewayHealthy && pointCount > 0 ? "ok" : gatewayHealthy ? "warning" : "bad",
        gatewayHealthy ? "El gateway de lectura está operativo." : "El gateway GPS/DVR no está saludable.",
      )}
    </div>
  </article>`;
}

function renderNodeAudit(): void {
  const node = auditNodeIndex == null ? null : managedNodes[auditNodeIndex];
  if (!node) {
    stopAuditPolling();
    viewMode = "manager";
    renderManager();
    return;
  }
  const services = auditSnapshot?.services ?? [];
  const gateway = services.find((service) => service.workload === "telemetry_gateway");
  const projector = services.find((service) => service.workload === "telemetry_projector");
  const broker = services.find((service) => service.workload === "broker_nats");
  const postgres = services.find((service) => service.workload === "datastore_postgres");
  const connector = services.find((service) => service.workload === "connectivity_connector");
  const terminals = auditSnapshot?.telemetry.terminals ?? [];
  const gatewayHealthy = auditServiceHealthy(gateway);
  const projectorHealthy = auditServiceHealthy(projector);
  const generatedAt = auditSnapshot
    ? new Date(Number(auditSnapshot.generatedAt) * 1_000).toLocaleTimeString()
    : "pendiente";
  const unresolved = auditSnapshot?.telemetry.unresolvedDeadLetters ?? 0;

  app.innerHTML = `
    <header class="topbar">
      <div class="brand-mark">A</div>
      <div>
        <span class="eyebrow">ACTIUM CONTROL PLANE</span>
        <h1>Auditoría GPS + DVR</h1>
      </div>
      <div class="version-pill">manager ${escapeHtml(system.payloadVersion)}</div>
      <button id="back-from-audit" class="secondary small">Volver al gestor</button>
    </header>
    <main class="manager-shell audit-shell">
      <section class="manager-header">
        <div>
          <span class="eyebrow">RECORRIDO LOCAL EN TIEMPO REAL</span>
          <h2>${escapeHtml(node.displayName)}</h2>
          <p>Traza recepción, proyección y lectura directamente desde Docker y PostgreSQL local. Se actualiza cada 3 segundos sin exponer otro endpoint ni revelar secretos.</p>
        </div>
        <div class="button-row">
          <span class="audit-updated">Corte ${escapeHtml(generatedAt)}</span>
          <button id="refresh-audit" class="secondary">Actualizar ahora</button>
        </div>
      </section>
      <section class="audit-service-grid">
        ${auditStage("Gateway GPS/DVR", gateway?.health || gateway?.state || "sin servicio", gatewayHealthy ? "ok" : "bad", gateway?.containerName || "telemetry_gateway")}
        ${auditStage("Broker NATS", broker?.health || broker?.state || "sin servicio", auditServiceHealthy(broker) ? "ok" : "bad", broker?.containerName || "broker_nats")}
        ${auditStage("Proyector", projector?.health || projector?.state || "sin servicio", projectorHealthy ? "ok" : "bad", projector?.containerName || "telemetry_projector")}
        ${auditStage("PostgreSQL", auditSnapshot?.databaseOk ? "consultable" : postgres?.health || "sin acceso", auditSnapshot?.databaseOk ? "ok" : "bad", auditSnapshot?.databaseError || postgres?.containerName || "datastore_postgres")}
        ${auditStage("Connectivity Edge", connector?.health || connector?.state || "sin servicio", auditServiceHealthy(connector) ? "ok" : "warning", connector?.containerName || "connectivity_connector")}
        ${auditStage("Dead letters", String(unresolved), unresolved === 0 ? "ok" : "bad", unresolved === 0 ? "Sin eventos irresueltos." : "Revise errores de contrato, autorización o proyección.")}
      </section>
      ${auditError ? `<section class="audit-error"><strong>No se pudo completar el corte</strong><pre>${escapeHtml(auditError)}</pre></section>` : ""}
      <nav class="audit-tabs" aria-label="Plano de auditoría">
        <button class="${auditTab === "gps" ? "active" : ""}" data-audit-tab="gps">GPS</button>
        <button class="${auditTab === "dvr" ? "active" : ""}" data-audit-tab="dvr">DVR</button>
      </nav>
      <section class="audit-terminal-list">
        ${terminals.length === 0
          ? `<div class="empty-manager"><strong>El nodo todavía no recibió telemetría</strong><span>Una terminal validada aparecerá aquí al entregar su primer heartbeat o lote GPS.</span></div>`
          : terminals.map((terminal) => auditTab === "gps"
            ? renderGpsAuditTerminal(terminal, gatewayHealthy, projectorHealthy)
            : renderDvrAuditTerminal(terminal, gatewayHealthy)).join("")}
      </section>
      ${auditSnapshot?.telemetry.recentDeadLetters?.length ? `
        <section class="audit-dead-letters">
          <h3>Dead letters recientes</h3>
          ${auditSnapshot.telemetry.recentDeadLetters.map((entry) => `
            <article>
              <strong>${escapeHtml(entry.category)} · ${escapeHtml(entry.stream)}</strong>
              <span>${escapeHtml(entry.reason)}</span>
              <small>${escapeHtml(auditTimestamp(entry.failedAt))} · ${escapeHtml(entry.subject)}</small>
            </article>`).join("")}
        </section>` : ""}
    </main>
    <div id="busy-overlay" class="busy-overlay ${auditRefreshInProgress && !auditSnapshot ? "visible" : ""}"><div class="spinner"></div><strong>Auditando recorrido…</strong><small>Consultando el nodo local.</small></div>
  `;
  bindAuditEvents();
}

function configurationValue(key: string, fallback = ""): string {
  return installation.config[key] ?? fallback;
}

function configurationChecked(key: string, fallback = false): string {
  const value = installation.config[key];
  const checked = value == null ? fallback : value.toLowerCase() === "true";
  return checked ? "checked" : "";
}

function endpointFromBase(baseUrl: string, port: string): string {
  try {
    const url = new URL(baseUrl);
    url.port = port;
    return url.toString().replace(/\/$/, "");
  } catch {
    return "";
  }
}

function renderNodeConfiguration(): void {
  const node = configurationNodeIndex == null ? null : managedNodes[configurationNodeIndex];
  if (!node) {
    viewMode = "manager";
    renderManager();
    return;
  }
  const connectivity = node.profiles.includes("connectivity");
  const networkMode = configuredNetworkMode();
  const configuredBaseUrl = configurationValue("DATA_PLANE_PUBLIC_BASE_URL", "http://127.0.0.1");
  const effectiveBaseUrl = networkMode === "local_only"
    ? "http://127.0.0.1"
    : networkMode === "trusted_lan"
      ? system.suggestedPublicBaseUrl
      : configuredBaseUrl;
  const fallbackOrder = configurationValue("CONNECTIVITY_FALLBACK_ORDER", "direct_data_plane");
  const publishedImages = configurationValue("ACTIUM_INSTALL_MODE") === "published_images"
    || configurationValue("ACTIUM_USE_PUBLISHED_IMAGES") === "true";
  app.innerHTML = `
    <header class="topbar">
      <div class="brand-mark">A</div>
      <div>
        <span class="eyebrow">ACTIUM CONTROL PLANE</span>
        <h1>Telemetry Node Manager</h1>
      </div>
      <div class="version-pill">manager ${escapeHtml(system.payloadVersion)}</div>
      <button id="back-to-manager" class="secondary small">Volver al gestor</button>
    </header>
    <main class="manager-shell configuration-shell">
      <section class="manager-header">
        <div>
          <span class="eyebrow">CONFIGURACIÓN LOCAL PERSISTENTE</span>
          <h2>${escapeHtml(node.displayName)}</h2>
          <p>Edita la topología completa sin volver a importar un paquete .adpe. La identidad, los perfiles autorizados, las claves públicas y los volúmenes permanecen intactos.</p>
        </div>
      </section>

      <section class="configuration-card">
        <div>
          <span class="eyebrow">TOPOLOGÍA Y PUBLICACIÓN</span>
          <h3>Servicios del nodo</h3>
          <p>Los cambios se validan con Docker Compose antes de considerarse aplicados.</p>
          <div class="inline-actions"><button id="config-assign-free-ports" class="secondary small">Asignar nuevos puertos libres</button><small>Úselo al convivir con otros nodos en este equipo.</small></div>
        </div>
        <div class="form-grid">
          <label>Nombre técnico<input value="${escapeHtml(configurationValue("ACTIUM_DATA_PLANE_PROJECT", node.projectName ?? ""))}" readonly /><small>La identidad técnica es inmutable; cambiar perfiles requiere un .adpe.</small></label>
          <label>Modo de red<select id="config-network-mode">${networkModeOptions(networkMode)}</select><small id="config-network-mode-help">${escapeHtml(networkModeDescription(networkMode))}</small></label>
          <label>Dirección de escucha<input id="config-bind-address" value="${escapeHtml(networkMode === "local_only" ? "127.0.0.1" : configurationValue("DATA_PLANE_BIND_ADDRESS", "0.0.0.0"))}" /></label>
          <label class="wide">URL accesible del nodo<input id="config-public-base-url" type="url" value="${escapeHtml(effectiveBaseUrl)}" /><small>Base local, LAN o VPN desde la que se derivan los endpoints observados.</small></label>
          <label class="wide">Orígenes CORS<input id="config-cors-origins" value="${escapeHtml(configurationValue("DATA_PLANE_CORS_ORIGINS", "https://localhost"))}" /></label>
          <label>Puerto GPS/DVR<input id="config-telemetry-port" type="number" value="${escapeHtml(configurationValue("TELEMETRY_PORT", "8090"))}" min="1" max="65535" /></label>
          <label>Puerto HT control<input id="config-radio-control-port" type="number" value="${escapeHtml(configurationValue("RADIO_CONTROL_PORT", "8100"))}" min="1" max="65535" /></label>
          <label>Puerto Prometheus<input id="config-prometheus-port" type="number" value="${escapeHtml(configurationValue("PROMETHEUS_PORT", "9090"))}" min="1" max="65535" /></label>
          <label>Puerto Grafana<input id="config-grafana-port" type="number" value="${escapeHtml(configurationValue("GRAFANA_PORT", "3001"))}" min="1" max="65535" /></label>
          <label class="wide">Telemetry Ingress HTTP(S)<input id="config-telemetry-ingress-public-url" type="url" value="${escapeHtml(configurationValue("TELEMETRY_INGRESS_PUBLIC_URL", endpointFromBase(effectiveBaseUrl, configurationValue("TELEMETRY_PORT", "8090"))))}" /><small>Endpoint exacto publicado a operadores y terminales.</small></label>
          <label class="wide">Telemetry Read HTTP(S)<input id="config-telemetry-read-public-url" type="url" value="${escapeHtml(configurationValue("TELEMETRY_READ_PUBLIC_URL", endpointFromBase(effectiveBaseUrl, configurationValue("TELEMETRY_PORT", "8090"))))}" /></label>
          <label class="wide">Métricas HTTP(S)<input id="config-metrics-public-url" type="url" value="${escapeHtml(configurationValue("METRICS_PUBLIC_URL", endpointFromBase(effectiveBaseUrl, configurationValue("PROMETHEUS_PORT", "9090"))))}" /></label>
          <label class="wide">Radio Control HTTP(S)<input id="config-radio-control-public-url" type="url" value="${escapeHtml(configurationValue("RADIO_CONTROL_PUBLIC_URL", endpointFromBase(effectiveBaseUrl, configurationValue("RADIO_CONTROL_PORT", "8100"))))}" /></label>
        </div>
        ${networkMode === "trusted_lan" && configuredBaseUrl !== system.suggestedPublicBaseUrl ? `<div class="callout warning"><strong>Nueva red detectada</strong><span>El nodo estaba publicado como ${escapeHtml(configuredBaseUrl)} y la ruta activa propone ${escapeHtml(system.suggestedPublicBaseUrl)}. Guardar aplicará la dirección actual.</span></div>` : ""}
      </section>

      <section class="configuration-card">
        <div>
          <span class="eyebrow">RADIO HT</span>
          <h3>TURN y LiveKit</h3>
          <p>La configuración queda disponible aunque el perfil todavía no esté instalado; activarlo sí requiere autorización .adpe.</p>
        </div>
        <div class="form-grid">
          <label>Realm TURN<input id="config-turn-realm" value="${escapeHtml(configurationValue("TURN_REALM"))}" placeholder="turn.aegis.example" /></label>
          <label>IP pública TURN<input id="config-turn-external-ip" value="${escapeHtml(configurationValue("TURN_EXTERNAL_IP"))}" placeholder="203.0.113.10" /></label>
          <label>Puerto TURN<input id="config-turn-port" type="number" value="${escapeHtml(configurationValue("TURN_PORT", "3478"))}" min="1" max="65535" /></label>
          <label>Puerto TURN TLS<input id="config-turn-tls-port" type="number" value="${escapeHtml(configurationValue("TURN_TLS_PORT", "5349"))}" min="1" max="65535" /></label>
          <label>Puerto UDP inicial<input id="config-turn-min-port" type="number" value="${escapeHtml(configurationValue("TURN_MIN_PORT", "49160"))}" min="1" max="65535" /></label>
          <label>Puerto UDP final<input id="config-turn-max-port" type="number" value="${escapeHtml(configurationValue("TURN_MAX_PORT", "49200"))}" min="1" max="65535" /></label>
          <label>IP anunciada LiveKit<input id="config-livekit-node-ip" value="${escapeHtml(configurationValue("LIVEKIT_NODE_IP"))}" placeholder="10.0.0.20" /></label>
          <label>URL pública LiveKit<input id="config-livekit-public-url" value="${escapeHtml(configurationValue("LIVEKIT_PUBLIC_URL"))}" placeholder="wss://livekit.aegis.example" /></label>
          <label>Puerto HTTP LiveKit<input id="config-livekit-http-port" type="number" value="${escapeHtml(configurationValue("LIVEKIT_HTTP_PORT", "7880"))}" min="1" max="65535" /></label>
          <label>Puerto RTC TCP LiveKit<input id="config-livekit-rtc-tcp-port" type="number" value="${escapeHtml(configurationValue("LIVEKIT_RTC_TCP_PORT", "7881"))}" min="1" max="65535" /></label>
          <label>UDP LiveKit inicial<input id="config-livekit-udp-min-port" type="number" value="${escapeHtml(configurationValue("LIVEKIT_UDP_MIN_PORT", "50000"))}" min="1" max="65535" /></label>
          <label>UDP LiveKit final<input id="config-livekit-udp-max-port" type="number" value="${escapeHtml(configurationValue("LIVEKIT_UDP_MAX_PORT", "50100"))}" min="1" max="65535" /></label>
          <label class="wide">TURN URLs<input id="config-turn-urls" value="${escapeHtml(configurationValue("TURN_URLS", configurationValue("TURN_REALM") ? `turn:${configurationValue("TURN_REALM")}:${configurationValue("TURN_PORT", "3478")}?transport=udp, turn:${configurationValue("TURN_REALM")}:${configurationValue("TURN_PORT", "3478")}?transport=tcp` : ""))}" placeholder="turn:turn.aegis.example:3478?transport=udp, turns:turn.aegis.example:5349" /><small>Lista separada por comas; coincide con el campo publicado desde Actium Center.</small></label>
        </div>
      </section>

      <section class="configuration-card">
        <div>
          <span class="eyebrow">CONNECTIVITY EDGE Y CONTINUIDAD</span>
          <h3>Transporte y fallbacks</h3>
          <p>Supabase permanece denegado salvo autorización explícita. Los secretos nunca se muestran ni se envían a Actium Center.</p>
        </div>
        ${connectivity ? `
          <div class="form-grid">
            <label class="wide">Connectivity Edge HTTPS<input id="config-connectivity-edge-control-url" type="url" value="${escapeHtml(configurationValue("CONNECTIVITY_EDGE_CONTROL_URL"))}" placeholder="https://connectivity.example.com" /></label>
            <label>Token de enrolamiento Edge<input id="config-connectivity-edge-enrollment-token" type="password" autocomplete="off" placeholder="${node.connectivityEdgeEnrollmentTokenConfigured ? "Configurado · dejar vacío para conservar" : "acen_..."}" /></label>
            <label>Token de relay interno<input id="config-connectivity-internal-relay-token" type="password" autocomplete="off" placeholder="${node.connectivityInternalRelayTokenConfigured ? "Configurado · dejar vacío para conservar" : "acer_..."}" /></label>
            <label>Rol<select id="config-connectivity-node-role"><option value="replica" ${configurationValue("CONNECTIVITY_NODE_ROLE", "replica") === "replica" ? "selected" : ""}>Réplica recuperable</option><option value="primary" ${configurationValue("CONNECTIVITY_NODE_ROLE") === "primary" ? "selected" : ""}>Primario</option></select></label>
            <label>Prioridad (0-1000)<input id="config-connectivity-node-priority" type="number" value="${escapeHtml(configurationValue("CONNECTIVITY_NODE_PRIORITY", "100"))}" min="0" max="1000" /></label>
            <label>Lotes por lectura (1-100)<input id="config-connectivity-pull-limit" type="number" value="${escapeHtml(configurationValue("CONNECTIVITY_PULL_LIMIT", "25"))}" min="1" max="100" /></label>
            <label>Orden de fallback<select id="config-connectivity-fallback-order">${fallbackOrderOptions(fallbackOrder)}</select><small>El selector sólo ordena los transportes habilitados.</small></label>
            <label class="toggle wide"><input id="config-connectivity-direct-data-plane-fallback-enabled" type="checkbox" ${configurationChecked("CONNECTIVITY_DIRECT_DATA_PLANE_FALLBACK_ENABLED", true)} /><span></span><div><strong>Fallback directo al Data Plane</strong><small>Usa el endpoint directo solo después de Connectivity Edge.</small></div></label>
            <label class="toggle wide critical-toggle"><input id="config-connectivity-supabase-fallback-enabled" type="checkbox" ${configurationChecked("CONNECTIVITY_SUPABASE_FALLBACK_ENABLED", false)} /><span></span><div><strong>Autorizar fallback Supabase</strong><small>Si está apagado, Aegis no consulta presencia, GPS ni DVR en Supabase cuando falla el Data Plane.</small></div></label>
          </div>` : `
          <div class="callout warning"><strong>Perfil Connectivity no instalado</strong><span>Importa un .adpe que autorice Connectivity para habilitar esta sección. La configuración ordinaria del nodo no puede ampliar privilegios.</span></div>
          <input id="config-connectivity-edge-control-url" type="hidden" value="" />
          <input id="config-connectivity-edge-enrollment-token" type="hidden" value="" />
          <input id="config-connectivity-internal-relay-token" type="hidden" value="" />
          <input id="config-connectivity-node-role" type="hidden" value="replica" />
          <input id="config-connectivity-node-priority" type="hidden" value="100" />
          <input id="config-connectivity-pull-limit" type="hidden" value="25" />
          <input id="config-connectivity-fallback-order" type="hidden" value="" />
          <input id="config-connectivity-direct-data-plane-fallback-enabled" type="checkbox" hidden />
          <input id="config-connectivity-supabase-fallback-enabled" type="checkbox" hidden />`}
      </section>

      <section class="configuration-card">
        <label class="toggle"><input id="config-published-images" type="checkbox" ${publishedImages ? "checked" : ""} /><span></span><div><strong>Usar imágenes publicadas</strong><small>Desactivado compila imágenes locales reproducibles desde el payload instalado.</small></div></label>
        <label class="toggle"><input id="config-restart-services" type="checkbox" ${system.dockerDaemon ? "checked" : ""} /><span></span><div><strong>Aplicar y recrear servicios</strong><small>Desactívalo para guardar los cambios como pendientes cuando Docker no esté disponible.</small></div></label>
        <div class="button-row wrap">
          <button id="save-node-configuration" class="primary">Guardar configuración</button>
          <button id="cancel-node-configuration" class="secondary">Cancelar</button>
        </div>
      </section>
      <section id="configuration-result" class="result ${managerResult ? managerResult.error ? "error" : "success" : "empty"}">
        <strong>${escapeHtml(managerResult?.message ?? "Configuración local")}</strong>
        <pre>${escapeHtml(managerResult?.output ?? "Los cambios todavía no fueron guardados.")}</pre>
      </section>
    </main>
    <div id="busy-overlay" class="busy-overlay ${busy ? "visible" : ""}"><div class="spinner"></div><strong>Aplicando configuración…</strong><small>Se restaurará la versión anterior si Docker rechaza los cambios.</small></div>
  `;
  bindConfigurationEvents();
  if (connectivity) synchronizeFallbackOrder("config-");
}

function render(): void {
  if (viewMode === "manager") {
    renderManager();
    return;
  }
  if (viewMode === "configuration") {
    renderNodeConfiguration();
    return;
  }
  if (viewMode === "audit") {
    renderNodeAudit();
    return;
  }
  const dependencyReady = system.dockerCli && system.composeV2 && system.dockerDaemon;
  const wizardNetworkMode = hasOperationalInstallation() ? configuredNetworkMode() : "local_only";
  const wizardBaseUrl = wizardNetworkMode === "local_only"
    ? "http://127.0.0.1"
    : wizardNetworkMode === "trusted_lan"
      ? system.suggestedPublicBaseUrl
      : configurationValue("DATA_PLANE_PUBLIC_BASE_URL", "");
  app.innerHTML = `
    <header class="topbar">
      <div class="brand-mark">A</div>
      <div>
        <span class="eyebrow">ACTIUM CONTROL PLANE</span>
        <h1>Telemetry Node Installer</h1>
      </div>
      <div class="version-pill">payload ${escapeHtml(system.payloadVersion)}</div>
      ${managedNodes.length > 0 ? '<button id="back-to-manager" class="secondary small">Volver al gestor</button>' : ""}
    </header>
    <main class="shell">
      <aside class="steps">
        <div class="node-summary">
          <span class="eyebrow">ESTE EQUIPO</span>
          <strong>${escapeHtml(system.platform)} / ${escapeHtml(system.architecture)}</strong>
          <small>${hasOperationalInstallation()
            ? `Nodo ${escapeHtml(installation.version ?? "detectado")}`
            : installation.recoverableIncompletePreparation
              ? "Preparación incompleta recuperable"
              : "Sin nodo administrado"}</small>
        </div>
        ${["Sistema", "Autoridad Actium", "Componentes", "Red (opcional)", "Instalar y operar"].map((title, index) => `
          <button class="step-button ${index === activeStep ? "active" : ""} ${validatedSteps[index] ? "done" : ""}" data-step="${index}" ${canAccessStep(index) ? "" : "disabled"}>
            <span>${validatedSteps[index] ? "✓" : index + 1}</span>${title}
          </button>`).join("")}
        <div class="authority-note">
          <strong>Actium-first</strong>
          <small>El nodo procesa telemetría localmente. Supabase no recibe el flujo continuo y permanece fuera del camino crítico.</small>
        </div>
      </aside>
      <section class="workspace">
        <div class="step-panel ${activeStep === 0 ? "active" : ""}" data-panel="0">
          <span class="eyebrow">PASO 1 · PRERREQUISITOS</span>
          <h2>Diagnóstico del host</h2>
          <p>El nodo se ejecuta como servicios Docker. El asistente comprueba el motor, Compose y el acceso al daemon antes de desplegar.</p>
          <div class="diagnostic-grid">
            <article>${statusChip(system.dockerCli, "Docker CLI", "Docker no instalado")}<small>Cliente Docker disponible en PATH.</small></article>
            <article>${statusChip(system.composeV2, "Compose v2", "Falta Compose v2")}<small>Orquestación de perfiles del nodo.</small></article>
            <article>${statusChip(system.dockerDaemon, "Daemon operativo", "Daemon detenido")}<small>En Windows, Docker Desktop debe estar abierto.</small></article>
          </div>
          <div class="callout ${dependencyReady ? "success" : "warning"}">
            <strong>${dependencyReady ? "Host listo para desplegar" : "Hay dependencias pendientes"}</strong>
            <span>${escapeHtml(system.dependencyMessage)}</span>
          </div>
          <div class="button-row">
            ${dependencyReady ? "" : `<button id="install-dependencies" class="primary" ${!system.dependencyInstallSupported ? "disabled" : ""}>Instalar dependencias</button>`}
            <button id="refresh-system" class="secondary">Actualizar diagnóstico</button>
          </div>
          ${system.platform === "windows" ? `<p class="footnote">La instalación habilita WSL 2 si falta y puede requerir reiniciar Windows o abrir Docker Desktop una vez.</p>` : `<p class="footnote">Después de agregar el usuario al grupo <code>docker</code>, puede ser necesario cerrar sesión y volver a entrar.</p>`}
        </div>

        <div class="step-panel ${activeStep === 1 ? "active" : ""}" data-panel="1">
          <span class="eyebrow">PASO 2 · CONTROL PLANE</span>
          <h2>Autoridad y enrolamiento</h2>
          <p>Importe el paquete <code>.adpe</code> emitido por Actium Center. El instalador verifica firma Ed25519, issuer, audiencia, despliegue y expiración antes de permitir continuar.</p>
          <div class="form-grid">
            <label class="wide">Directorio del nodo<input id="install-dir" value="${escapeHtml(system.defaultInstallDir)}" /><small>Al reabrir el instalador se detectan los componentes existentes y sólo se agregan perfiles.</small></label>
            <div class="wide inline-actions"><button id="inspect-installation" class="secondary small">Detectar instalación</button><span id="installation-state">${hasOperationalInstallation()
              ? "Instalación administrada y operativa detectada"
              : installation.recoverableIncompletePreparation
                ? `Preparación incompleta (${escapeHtml(installation.status ?? "failed")})`
                : "Destino nuevo"}</span></div>
            <label class="file-field wide">Paquete de enrolamiento Actium<input id="bootstrap-package" type="file" accept=".adpe,application/vnd.actium.data-plane-enrollment,text/plain" /><span id="bootstrap-state">${bootstrapValidation ? `${escapeHtml(bootstrapValidation.deploymentName)} · generación ${bootstrapValidation.generation} · firma válida` : "Seleccione el archivo .adpe descargado desde Actium Center"}</span></label>
          </div>
          ${bootstrapValidation ? `<div class="callout success"><strong>Paquete soberano verificado</strong><span>${escapeHtml(bootstrapValidation.deploymentCode)} · expira ${escapeHtml(new Date(bootstrapValidation.expiresAtUnixSeconds * 1000).toLocaleString("es-AR"))} · instalador mínimo ${escapeHtml(bootstrapValidation.installerMinVersion)} · perfiles autorizados: ${escapeHtml(bootstrapValidation.profiles.join(", "))}</span></div>` : `<div class="callout warning"><strong>Enrolamiento pendiente</strong><span>No se habilitarán Componentes ni Red hasta validar un .adpe vigente.</span></div>`}
          ${hasDeploymentConflict() ? `<div class="callout warning">
            <strong>Preparación incompleta de otro despliegue</strong>
            <span>El directorio conserva evidencia de ${escapeHtml(installation.deploymentCode ?? installation.deploymentId ?? "otro despliegue")}, pero no existe un nodo operativo. Para instalar ${escapeHtml(bootstrapValidation?.deploymentCode ?? "el nuevo despliegue")}, archive primero esa preparación incompleta.</span>
            ${installation.lastError ? `<small>Último error: ${escapeHtml(installation.lastError)}</small>` : ""}
            <button id="archive-incomplete-preparation" class="secondary small">Archivar preparación y liberar destino</button>
          </div>` : installation.recoverableIncompletePreparation && bootstrapValidation?.deploymentId === installation.deploymentId ? `<div class="callout warning">
            <strong>Reintento seguro disponible</strong>
            <span>La preparación anterior de este mismo despliegue no llegó a ser operativa. Puede continuar y el instalador reintentará sobre el mismo destino.</span>
            ${installation.lastError ? `<small>Último error: ${escapeHtml(installation.lastError)}</small>` : ""}
          </div>` : ""}
        </div>

        <div class="step-panel ${activeStep === 2 ? "active" : ""}" data-panel="2">
          <span class="eyebrow">PASO 3 · CAPACIDADES</span>
          <div class="title-row"><div><h2>Componentes del nodo</h2><p>Seleccione un nodo completo o sólo los servicios requeridos por esta organización.</p></div><button id="select-all" class="secondary small">Seleccionar todo</button></div>
          <div class="profile-grid">${profileCards()}</div>
          ${hasOperationalInstallation() ? `<div class="callout success"><strong>Ampliación aditiva</strong><span>Los perfiles instalados permanecen bloqueados. El asistente conserva secretos, estado y volúmenes existentes.</span></div>` : ""}
        </div>

        <div class="step-panel ${activeStep === 3 ? "active" : ""}" data-panel="3">
          <span class="eyebrow">PASO 4 · TOPOLOGÍA</span>
          <h2>Red y publicación</h2>
          <p>Puede aceptar una configuración local segura y completar la publicación después desde el botón <strong>Configurar</strong> del gestor.</p>
          <label class="toggle defer-network-toggle"><input id="defer-network-configuration" type="checkbox" ${networkConfigurationDeferred ? "checked" : ""} /><span></span><div><strong>Configurar red y publicación después</strong><small>Conserva la red actual al ampliar; en un nodo nuevo usa loopback y no expone servicios a la LAN.</small></div></label>
          <div class="inline-actions"><button id="assign-free-ports" class="secondary small">Asignar puertos libres</button><small>Comprueba procesos y otros nodos del equipo, incluidos TURN y LiveKit.</small></div>
          <div id="step-four-requirements" class="callout warning"></div>
          <div id="wizard-network-fields" class="form-grid ${networkConfigurationDeferred ? "deferred" : ""}">
            <label>Nombre técnico<input id="project-name" value="actium-data-plane-node-01" /></label>
            <label>Modo de red<select id="network-mode">${networkModeOptions(wizardNetworkMode)}</select><small id="network-mode-help">${escapeHtml(networkModeDescription(wizardNetworkMode))}</small></label>
            <label>Dirección de escucha<input id="bind-address" value="${wizardNetworkMode === "local_only" ? "127.0.0.1" : "0.0.0.0"}" /></label>
            <label>URL accesible del nodo<input id="public-base-url" type="url" value="${escapeHtml(wizardBaseUrl)}" /><small>Dirección local, LAN o VPN que usarán las terminales y Aegis Control.</small></label>
            <label class="wide">Orígenes CORS<input id="cors-origins" value="http://localhost:5173,http://tauri.localhost,https://localhost" /></label>
            <label>Puerto GPS/DVR<input id="telemetry-port" type="number" value="8090" min="1" max="65535" /></label>
            <label>Puerto HT control<input id="radio-control-port" type="number" value="8100" min="1" max="65535" /></label>
            <label>Puerto Prometheus<input id="prometheus-port" type="number" value="9090" min="1" max="65535" /></label>
            <label>Puerto Grafana<input id="grafana-port" type="number" value="3001" min="1" max="65535" /></label>
          </div>
          <details>
            <summary>Configuración avanzada de TURN y LiveKit</summary>
            <div class="form-grid details-grid">
              <label>Realm TURN<input id="turn-realm" placeholder="turn.aegis.example" /></label>
              <label>IP pública TURN<input id="turn-external-ip" placeholder="203.0.113.10" /></label>
              <label>Puerto TURN<input id="turn-port" type="number" value="3478" min="1" max="65535" /></label>
              <label>Puerto TURN TLS<input id="turn-tls-port" type="number" value="5349" min="1" max="65535" /></label>
              <label>Puerto UDP inicial<input id="turn-min-port" type="number" value="49160" /></label>
              <label>Puerto UDP final<input id="turn-max-port" type="number" value="49200" /></label>
              <label>IP anunciada LiveKit<input id="livekit-node-ip" placeholder="10.0.0.20" /></label>
              <label>URL pública LiveKit<input id="livekit-public-url" placeholder="wss://livekit.aegis.example" /></label>
              <label>Puerto HTTP LiveKit<input id="livekit-http-port" type="number" value="7880" min="1" max="65535" /></label>
              <label>Puerto RTC TCP LiveKit<input id="livekit-rtc-tcp-port" type="number" value="7881" min="1" max="65535" /></label>
              <label>UDP LiveKit inicial<input id="livekit-udp-min-port" type="number" value="50000" min="1" max="65535" /></label>
              <label>UDP LiveKit final<input id="livekit-udp-max-port" type="number" value="50100" min="1" max="65535" /></label>
            </div>
          </details>
          <details>
            <summary>Connectivity Edge y recuperación multi-nodo</summary>
            <div class="form-grid details-grid">
              <label class="wide">Control de Connectivity Edge<input id="connectivity-edge-control-url" type="url" placeholder="https://connectivity.example.com" /><small>Plano independiente. No debe apuntar a los cores Supabase de Actium o Aegis.</small></label>
              <label>Token de enrolamiento Edge<input id="connectivity-edge-enrollment-token" type="password" autocomplete="off" placeholder="acen_..." /></label>
              <label>Token de relay interno<input id="connectivity-internal-relay-token" type="password" autocomplete="off" placeholder="acer_..." /></label>
              <label>Rol inicial<select id="connectivity-node-role"><option value="replica">Réplica recuperable</option><option value="primary">Primario</option></select></label>
              <label>Prioridad del nodo<input id="connectivity-node-priority" type="number" value="100" min="0" max="1000" /><small>Menor valor gana al elegir réplica.</small></label>
              <label>Lotes por lectura<input id="connectivity-pull-limit" type="number" value="25" min="1" max="100" /><small>Controla presión y memoria del relay.</small></label>
              <label>Orden de fallback<select id="connectivity-fallback-order">${fallbackOrderOptions(bootstrapValidation?.connectivityPolicy?.fallbackOrder.join(",") || "direct_data_plane")}</select><small>El selector sólo ordena los transportes habilitados.</small></label>
              <label class="toggle wide"><input id="connectivity-direct-data-plane-fallback-enabled" type="checkbox" checked /><span></span><div><strong>Fallback directo al Data Plane</strong><small>Usa el endpoint del nodo sólo después de agotar Connectivity Edge.</small></div></label>
              <label class="toggle wide"><input id="connectivity-supabase-fallback-enabled" type="checkbox" /><span></span><div><strong>Fallback Supabase</strong><small>Transitorio y opcional. Nunca convierte Supabase en core de Connectivity Edge.</small></div></label>
              <div class="callout success wide"><strong>Prioridad invariable</strong><span>Cola durable local → Connectivity Edge → fallbacks habilitados en el orden seleccionado. La cola local no puede desactivarse.</span></div>
            </div>
          </details>
          <label class="toggle"><input id="published-images" type="checkbox" /><span></span><div><strong>Usar imágenes publicadas</strong><small>Desactivado: compila imágenes locales reproducibles desde el payload incluido.</small></div></label>
        </div>

        <div class="step-panel ${activeStep === 4 ? "active" : ""}" data-panel="4">
          <span class="eyebrow">PASO 5 · EJECUCIÓN</span>
          <h2>${hasOperationalInstallation() ? "Ampliar o administrar el nodo" : "Instalar el nodo"}</h2>
          <div class="review-card">
            <div><span>Host</span><strong>${escapeHtml(system.platform)} ${escapeHtml(system.architecture)}</strong></div>
            <div><span>Modelo</span><strong>Control Plane Actium + Data Plane local</strong></div>
            <div><span>Modo</span><strong>${hasOperationalInstallation() ? "Ampliación sin pérdida de estado" : installation.recoverableIncompletePreparation ? "Reintento de preparación incompleta" : "Enrolamiento inicial"}</strong></div>
            <div><span>Red</span><strong id="review-network-mode">${networkConfigurationDeferred ? "Diferida · loopback seguro" : escapeHtml(networkModeDescription(wizardNetworkMode))}</strong></div>
          </div>
          <label class="toggle"><input id="prepare-only" type="checkbox" /><span></span><div><strong>Sólo preparar</strong><small>Genera configuración y secretos pero no inicia los contenedores.</small></div></label>
          <button id="apply-installation" class="primary install-button">${hasOperationalInstallation() ? "Aplicar ampliación" : "Instalar y enrolar"}</button>
          <div class="operations ${hasOperationalInstallation() ? "visible" : ""}">
            <h3>Operación local</h3>
            <div class="button-row wrap">
              ${["status", "verify", "start", "stop", "restart", "update", "logs"].map((action) => `<button class="secondary node-action" data-action="${action}">${action}</button>`).join("")}
            </div>
          </div>
          <div id="result" class="result empty"><strong>Registro de instalación</strong><pre>Esperando una operación…</pre></div>
        </div>

        <div id="step-error" class="step-error" role="alert"></div>
        <footer class="navigation">
          <button id="previous" class="secondary" ${activeStep === 0 ? "disabled" : ""}>Anterior</button>
          <span>Paso ${activeStep + 1} de 5</span>
          <button id="next" class="primary" ${activeStep === 4 ? "disabled" : ""}>Continuar</button>
        </footer>
      </section>
    </main>
    <div id="busy-overlay" class="busy-overlay ${busy ? "visible" : ""}"><div class="spinner"></div><strong>Procesando…</strong><small>No cierre el instalador.</small></div>
  `;
  bindEvents();
  applyExistingConfig();
  updateNavigationState();
}

function input(id: string): HTMLInputElement {
  const element = document.querySelector<HTMLInputElement>(`#${id}`);
  if (!element) throw new Error(`No se encontro #${id}.`);
  return element;
}

function setInput(id: string, value: string | undefined): void {
  if (!value) return;
  const element = document.querySelector<HTMLInputElement>(`#${id}`);
  if (element) element.value = value;
}

function applyExistingConfig(): void {
  const config = installation.config;
  setInput("install-dir", system.defaultInstallDir);
  setInput("control-endpoint", config.ACTIUM_CONTROL_ENDPOINT);
  setInput("terminal-issuer", config.ACTIUM_TERMINAL_ISSUER);
  setInput("operator-issuer", config.ACTIUM_OPERATOR_ISSUER);
  setInput(
    "project-name",
    hasOperationalInstallation()
      ? config.ACTIUM_PROJECT_NAME
      : bootstrapValidation?.deploymentCode ?? config.ACTIUM_PROJECT_NAME,
  );
  setInput("network-mode", validNetworkMode(config.DATA_PLANE_NETWORK_MODE) ? config.DATA_PLANE_NETWORK_MODE : configuredNetworkMode());
  setInput("bind-address", config.DATA_PLANE_BIND_ADDRESS);
  setInput("public-base-url", config.DATA_PLANE_PUBLIC_BASE_URL);
  setInput("cors-origins", config.DATA_PLANE_CORS_ORIGINS);
  setInput("telemetry-port", config.TELEMETRY_PORT);
  setInput("radio-control-port", config.RADIO_CONTROL_PORT);
  setInput("prometheus-port", config.PROMETHEUS_PORT);
  setInput("grafana-port", config.GRAFANA_PORT);
  setInput("turn-realm", config.TURN_REALM);
  setInput("turn-external-ip", config.TURN_EXTERNAL_IP);
  setInput("turn-port", config.TURN_PORT);
  setInput("turn-tls-port", config.TURN_TLS_PORT);
  setInput("turn-min-port", config.TURN_MIN_PORT);
  setInput("turn-max-port", config.TURN_MAX_PORT);
  setInput("livekit-node-ip", config.LIVEKIT_NODE_IP);
  setInput("livekit-public-url", config.LIVEKIT_PUBLIC_URL);
  setInput("livekit-http-port", config.LIVEKIT_HTTP_PORT);
  setInput("livekit-rtc-tcp-port", config.LIVEKIT_RTC_TCP_PORT);
  setInput("livekit-udp-min-port", config.LIVEKIT_UDP_MIN_PORT);
  setInput("livekit-udp-max-port", config.LIVEKIT_UDP_MAX_PORT);
  setInput("connectivity-edge-control-url", config.CONNECTIVITY_EDGE_CONTROL_URL ?? bootstrapValidation?.connectivityPolicy?.edgeControlUrl);
  setInput("connectivity-node-role", config.CONNECTIVITY_NODE_ROLE ?? bootstrapValidation?.connectivityPolicy?.nodeRole);
  setInput("connectivity-node-priority", config.CONNECTIVITY_NODE_PRIORITY ?? bootstrapValidation?.connectivityPolicy?.nodePriority.toString());
  setInput("connectivity-pull-limit", config.CONNECTIVITY_PULL_LIMIT ?? bootstrapValidation?.connectivityPolicy?.pullLimit.toString());
  setInput("connectivity-fallback-order", config.CONNECTIVITY_FALLBACK_ORDER ?? bootstrapValidation?.connectivityPolicy?.fallbackOrder.join(","));
  setChecked(
    "connectivity-direct-data-plane-fallback-enabled",
    config.CONNECTIVITY_DIRECT_DATA_PLANE_FALLBACK_ENABLED,
    bootstrapValidation?.connectivityPolicy?.directDataPlaneFallbackEnabled ?? true,
  );
  setChecked(
    "connectivity-supabase-fallback-enabled",
    config.CONNECTIVITY_SUPABASE_FALLBACK_ENABLED,
    bootstrapValidation?.connectivityPolicy?.supabaseFallbackEnabled ?? false,
  );
  const published = document.querySelector<HTMLInputElement>("#published-images");
  if (published) published.checked = config.ACTIUM_USE_PUBLISHED_IMAGES === "true" || config.ACTIUM_INSTALL_MODE === "published_images";
}

function setChecked(id: string, configured: string | undefined, fallback: boolean): void {
  const element = document.querySelector<HTMLInputElement>(`#${id}`);
  if (!element) return;
  element.checked = configured === undefined ? fallback : configured.toLowerCase() === "true";
}

function changeStep(nextStep: number): void {
  const bounded = Math.max(0, Math.min(4, nextStep));
  if (!canAccessStep(bounded)) return;
  activeStep = bounded;
  showStepError("");
  updateNavigationState();
}

function canAccessStep(step: number): boolean {
  if (step <= 0) return true;
  for (let prerequisite = 0; prerequisite < step; prerequisite += 1) {
    if (!validatedSteps[prerequisite]) return false;
  }
  return true;
}

function updateNavigationState(): void {
  document.querySelectorAll<HTMLButtonElement>("[data-step]").forEach((button) => {
    const index = Number(button.dataset.step);
    button.classList.toggle("active", index === activeStep);
    button.classList.toggle("done", validatedSteps[index]);
    button.disabled = busy || !canAccessStep(index);
    const circle = button.querySelector("span");
    if (circle) circle.textContent = validatedSteps[index] ? "✓" : String(index + 1);
  });
  document.querySelectorAll<HTMLElement>("[data-panel]").forEach((panel) => {
    panel.classList.toggle("active", Number(panel.dataset.panel) === activeStep);
  });
  const previous = document.querySelector<HTMLButtonElement>("#previous");
  const next = document.querySelector<HTMLButtonElement>("#next");
  if (previous) previous.disabled = busy || activeStep === 0;
  if (next) next.disabled = busy || activeStep === 4 || !isStepLocallyComplete(activeStep);
  const counter = document.querySelector(".navigation span");
  if (counter) counter.textContent = `Paso ${activeStep + 1} de 5`;
  const networkReview = document.querySelector<HTMLElement>("#review-network-mode");
  const modeSelect = document.querySelector<HTMLSelectElement>("#network-mode");
  if (networkReview && modeSelect && validNetworkMode(modeSelect.value)) {
    networkReview.textContent = networkConfigurationDeferred
      ? `Diferida · ${hasOperationalInstallation() ? "conserva la configuración vigente" : "loopback seguro"}`
      : networkModeDescription(modeSelect.value);
  }
  updateStepFourRequirements();
}

function showStepError(message: string): void {
  const target = document.querySelector<HTMLDivElement>("#step-error");
  if (!target) return;
  target.textContent = message;
  target.classList.toggle("visible", Boolean(message));
}

function isStepLocallyComplete(step: number): boolean {
  if (step === 0) return system.dockerCli && system.composeV2 && system.dockerDaemon;
  if (step === 1) return Boolean(input("install-dir").value.trim() && bootstrapJws && bootstrapValidation?.valid && !hasDeploymentConflict());
  if (step === 2) return selectedProfiles().length > 0;
  if (step === 3) return stepFourBlockers().length === 0;
  return true;
}

function stepFourBlockers(): string[] {
  const blockers: string[] = [];
  if (!validNetworkMode(input("network-mode").value)) blockers.push("Seleccione un modo de red válido.");
  const required = ["project-name", "bind-address", "public-base-url", "cors-origins", "telemetry-port", "radio-control-port", "prometheus-port", "grafana-port"];
  if (required.some((id) => !input(id).value.trim() || !input(id).checkValidity())) {
    blockers.push(networkConfigurationDeferred
      ? "La configuración local segura no pudo completarse automáticamente."
      : "Complete nombre, bind, URL, CORS y puertos principales.");
  }
  if (!/^[a-z0-9][a-z0-9._-]{2,79}$/.test(input("project-name").value.trim())) {
    blockers.push("El nombre técnico debe usar 3-80 caracteres a-z, 0-9, punto, guion o guion bajo.");
  }
  try {
    const publicUrl = new URL(input("public-base-url").value.trim());
    if (!["http:", "https:"].includes(publicUrl.protocol)) blockers.push("La URL accesible debe usar HTTP(S).");
    if (input("network-mode").value === "local_only" && !["127.0.0.1", "localhost"].includes(publicUrl.hostname)) {
      blockers.push("Sólo este equipo debe publicarse por loopback.");
    }
  } catch {
    blockers.push("La URL accesible del nodo no es válida.");
  }
  const selected = new Set(selectedProfiles());
  const advancedPortIds = [
    ...(selected.has("radio-turn") ? ["turn-port", "turn-tls-port", "turn-min-port", "turn-max-port"] : []),
    ...(selected.has("radio-livekit")
      ? ["livekit-http-port", "livekit-rtc-tcp-port", "livekit-udp-min-port", "livekit-udp-max-port"]
      : []),
  ];
  if (advancedPortIds.some((id) => !input(id).value.trim() || !input(id).checkValidity())) {
    blockers.push("Los puertos avanzados deben estar entre 1 y 65535.");
  }
  const claimedPorts = new Map<string, string>();
  const claimPort = (transport: "TCP" | "UDP", port: number, label: string): void => {
    const key = `${transport}:${port}`;
    const previous = claimedPorts.get(key);
    if (previous) blockers.push(`${previous} y ${label} no pueden compartir ${port}/${transport}.`);
    else claimedPorts.set(key, label);
  };
  if (selected.has("telemetry") || selected.has("connectivity")) claimPort("TCP", integerValue("telemetry-port"), "GPS/DVR");
  if (["radio-control", "radio-saf", "radio-turn", "radio-livekit"].some((profile) => selected.has(profile))) {
    claimPort("TCP", integerValue("radio-control-port"), "HT control");
  }
  if (selected.has("observability")) {
    claimPort("TCP", integerValue("prometheus-port"), "Prometheus");
    claimPort("TCP", integerValue("grafana-port"), "Grafana");
  }
  if (selected.has("radio-turn")) {
    if (!input("turn-realm").value.trim()) blockers.push("TURN está seleccionado: defina su realm.");
    const turnPort = integerValue("turn-port");
    const turnTlsPort = integerValue("turn-tls-port");
    const turnMin = integerValue("turn-min-port");
    const turnMax = integerValue("turn-max-port");
    claimPort("TCP", turnPort, "TURN");
    claimPort("UDP", turnPort, "TURN");
    claimPort("TCP", turnTlsPort, "TURN TLS");
    if (turnMin > turnMax) blockers.push("TURN está seleccionado: ordene correctamente el rango UDP.");
    else for (let port = turnMin; port <= turnMax; port += 1) claimPort("UDP", port, "TURN relay");
  }
  if (selected.has("radio-livekit")) {
    if (!input("livekit-node-ip").value.trim()) blockers.push("LiveKit está seleccionado: defina la IP anunciada.");
    if (!input("livekit-public-url").value.trim().startsWith("wss://")) blockers.push("LiveKit está seleccionado: defina una URL pública wss://.");
    const livekitMin = integerValue("livekit-udp-min-port");
    const livekitMax = integerValue("livekit-udp-max-port");
    claimPort("TCP", integerValue("livekit-http-port"), "LiveKit HTTP");
    claimPort("TCP", integerValue("livekit-rtc-tcp-port"), "LiveKit RTC");
    if (livekitMin > livekitMax) blockers.push("LiveKit está seleccionado: ordene correctamente el rango UDP.");
    else for (let port = livekitMin; port <= livekitMax; port += 1) claimPort("UDP", port, "LiveKit RTC");
  }
  if (selected.has("connectivity") && !installation.profiles.includes("connectivity")) {
    if (!input("connectivity-edge-control-url").value.trim().startsWith("https://")) {
      blockers.push("Connectivity Edge está siendo agregado: defina su URL de control HTTPS.");
    }
    if (!/^acen_[A-Za-z0-9_-]{40,}$/.test(input("connectivity-edge-enrollment-token").value.trim())) {
      blockers.push("Connectivity Edge está siendo agregado: ingrese el token de enrolamiento acen_… completo.");
    }
    if (!/^acer_[A-Za-z0-9_-]{40,}$/.test(input("connectivity-internal-relay-token").value.trim())) {
      blockers.push("Connectivity Edge está siendo agregado: ingrese el token de relay acer_… completo.");
    }
  }
  if (selected.has("connectivity")) {
    if (integerValue("connectivity-node-priority") < 0 || integerValue("connectivity-node-priority") > 1000) {
      blockers.push("Connectivity: la prioridad debe estar entre 0 y 1000.");
    }
    if (integerValue("connectivity-pull-limit") < 1 || integerValue("connectivity-pull-limit") > 100) {
      blockers.push("Connectivity: los lotes por lectura deben estar entre 1 y 100.");
    }
  }
  return [...new Set(blockers)];
}

function updateStepFourRequirements(): void {
  const target = document.querySelector<HTMLDivElement>("#step-four-requirements");
  if (!target) return;
  const blockers = stepFourBlockers();
  target.classList.toggle("warning", blockers.length > 0);
  target.classList.toggle("success", blockers.length === 0);
  target.innerHTML = blockers.length > 0
    ? `<strong>Requisitos pendientes</strong><span>${blockers.map(escapeHtml).join(" · ")}</span>`
    : `<strong>Paso listo</strong><span>${networkConfigurationDeferred ? "La red se conservará para configurarla después; los perfiles seleccionados tienen sus requisitos operativos completos." : "La red y los perfiles seleccionados están completos."}</span>`;
}

async function validateStep(step: number): Promise<void> {
  showStepError("");
  if (!isStepLocallyComplete(step)) {
    throw new Error(step === 3 ? stepFourBlockers().join(" ") : "Complete todos los campos obligatorios de este paso.");
  }
  if (step === 0) {
    const latest = await invoke<SystemInfo>("get_system_info");
    system = latest;
    if (!(latest.dockerCli && latest.composeV2 && latest.dockerDaemon)) throw new Error("Docker CLI, Compose v2 y el daemon deben estar operativos.");
  } else if (step === 1) {
    bootstrapValidation = await invoke<BootstrapValidation>("validate_bootstrap", { request: { bootstrapJws } });
    const installDir = input("install-dir").value.trim();
    installation = await invoke<InstallationState>("inspect_installation", { request: { installDir } });
    system.defaultInstallDir = installDir;
    if (hasDeploymentConflict()) {
      throw new Error("Archive la preparación fallida del despliegue anterior antes de continuar.");
    }
  } else if (step === 2) {
    const unauthorized = selectedProfiles().filter((profile) => !(hasOperationalInstallation() && installation.profiles.includes(profile)) && !bootstrapValidation?.profiles.includes(profile));
    if (unauthorized.length > 0) throw new Error(`El paquete .adpe no autoriza: ${unauthorized.join(", ")}.`);
    if (
      !hasOperationalInstallation()
      && bootstrapValidation
      && autoAssignedPortsDeploymentId !== bootstrapValidation.deploymentId
    ) {
      await assignAvailablePorts(false);
    }
  } else if (step === 3) {
    await invoke<ActionResult>("validate_installation_request", { request: installRequest() });
  }
}

async function advanceTo(nextStep: number): Promise<void> {
  if (nextStep <= activeStep) {
    changeStep(nextStep);
    return;
  }
  if (canAccessStep(nextStep)) {
    changeStep(nextStep);
    return;
  }
  if (nextStep !== activeStep + 1) return;
  setBusy(true);
  try {
    await validateStep(activeStep);
    validatedSteps[activeStep] = true;
    changeStep(nextStep);
  } catch (error) {
    showStepError(String(error));
  } finally {
    setBusy(false);
    updateNavigationState();
  }
}

function invalidateFrom(step: number): void {
  for (let index = Math.max(0, step); index < validatedSteps.length; index += 1) {
    validatedSteps[index] = false;
  }
  if (!canAccessStep(activeStep)) activeStep = step;
  showStepError("");
  updateNavigationState();
}

function setBusy(value: boolean): void {
  busy = value;
  document.querySelector("#busy-overlay")?.classList.toggle("visible", value);
}

function showResult(message: string, output = "", error = false): void {
  const result = document.querySelector<HTMLDivElement>("#result");
  if (!result) return;
  result.className = `result ${error ? "error" : "success"}`;
  result.innerHTML = `<strong>${escapeHtml(message)}</strong><pre>${escapeHtml(output || "Operación completada.")}</pre>`;
}

async function refreshSystem(): Promise<void> {
  setBusy(true);
  try {
    system = await invoke<SystemInfo>("get_system_info");
    validatedSteps = [false, false, false, false, false];
    activeStep = 0;
    render();
  } catch (error) {
    showResult("No se pudo actualizar el diagnóstico", String(error), true);
  } finally {
    setBusy(false);
  }
}

async function inspectInstallation(): Promise<void> {
  const installDir = input("install-dir").value.trim();
  setBusy(true);
  try {
    installation = await invoke<InstallationState>("inspect_installation", { request: { installDir } });
    system.defaultInstallDir = installDir;
    render();
  } catch (error) {
    showResult("No se pudo inspeccionar el destino", String(error), true);
  } finally {
    setBusy(false);
  }
}

async function loadBootstrap(fileInput: HTMLInputElement): Promise<void> {
  const file = fileInput.files?.[0];
  if (!file) return;
  setBusy(true);
  try {
    const contents = (await file.text()).trim();
    const validated = await invoke<BootstrapValidation>("validate_bootstrap", { request: { bootstrapJws: contents } });
    bootstrapJws = contents;
    bootstrapValidation = validated;
    autoAssignedPortsDeploymentId = null;
    if (wizardTargetPinned) {
      const installDir = input("install-dir").value.trim();
      installation = await invoke<InstallationState>("inspect_installation", { request: { installDir } });
      system.defaultInstallDir = installDir;
    } else {
      const target = await invoke<InstallationTarget>("suggest_installation_target", {
        request: { bootstrapJws: contents },
      });
      installation = target.installation;
      system.defaultInstallDir = target.installDir;
      wizardTargetPinned = target.matchedExisting;
    }
    activeStep = 1;
    invalidateFrom(1);
    render();
  } catch (error) {
    bootstrapJws = "";
    bootstrapValidation = null;
    invalidateFrom(1);
    showStepError(`Paquete .adpe rechazado: ${String(error)}`);
  } finally {
    setBusy(false);
    updateNavigationState();
  }
}

function selectedProfiles(): string[] {
  const checked = [...document.querySelectorAll<HTMLInputElement>('input[name="profiles"]:checked')].map((element) => element.value);
  const installedProfiles = hasOperationalInstallation() ? installation.profiles : [];
  return [...new Set([...installedProfiles, ...checked])];
}

function integerValue(id: string): number {
  return Number.parseInt(input(id).value, 10);
}

function applyNetworkPortPlan(plan: NetworkPortPlan, prefix: "" | "config-" = ""): void {
  const derivedEndpoints = prefix === "config-"
    ? [
        ["config-telemetry-ingress-public-url", "config-telemetry-port"],
        ["config-telemetry-read-public-url", "config-telemetry-port"],
        ["config-metrics-public-url", "config-prometheus-port"],
        ["config-radio-control-public-url", "config-radio-control-port"],
      ].map(([endpointId, portId]) => ({
        endpointId,
        followsBase: input(endpointId).value === endpointFromBase(
          input("config-public-base-url").value,
          input(portId).value,
        ),
      }))
    : [];
  const previousTurnPort = prefix === "config-" ? input("config-turn-port").value : "";
  const previousLiveKitHttpPort = prefix === "config-" ? input("config-livekit-http-port").value : "";
  const values: Array<[string, number]> = [
    ["telemetry-port", plan.telemetryPort],
    ["radio-control-port", plan.radioControlPort],
    ["prometheus-port", plan.prometheusPort],
    ["grafana-port", plan.grafanaPort],
    ["turn-port", plan.turnPort],
    ["turn-tls-port", plan.turnTlsPort],
    ["turn-min-port", plan.turnMinPort],
    ["turn-max-port", plan.turnMaxPort],
    ["livekit-http-port", plan.livekitHttpPort],
    ["livekit-rtc-tcp-port", plan.livekitRtcTcpPort],
    ["livekit-udp-min-port", plan.livekitUdpMinPort],
    ["livekit-udp-max-port", plan.livekitUdpMaxPort],
  ];
  for (const [id, value] of values) input(`${prefix}${id}`).value = String(value);
  if (prefix !== "config-") return;

  const publicBaseUrl = input("config-public-base-url").value;
  for (const derived of derivedEndpoints) {
    if (!derived.followsBase) continue;
    const portId = derived.endpointId.includes("metrics")
      ? "config-prometheus-port"
      : derived.endpointId.includes("radio-control")
        ? "config-radio-control-port"
        : "config-telemetry-port";
    input(derived.endpointId).value = endpointFromBase(publicBaseUrl, input(portId).value);
  }
  if (previousTurnPort) {
    const turnPortPattern = new RegExp(`:${previousTurnPort}(?=[/?]|$)`, "g");
    input("config-turn-urls").value = input("config-turn-urls").value.replace(
      turnPortPattern,
      `:${plan.turnPort}`,
    );
  }
  if (previousLiveKitHttpPort) {
    const liveKitPortPattern = new RegExp(`:${previousLiveKitHttpPort}(?=[/?]|$)`);
    input("config-livekit-public-url").value = input("config-livekit-public-url").value.replace(
      liveKitPortPattern,
      `:${plan.livekitHttpPort}`,
    );
  }
}

async function assignAvailablePorts(showConfirmation = true): Promise<void> {
  const plan = await invoke<NetworkPortPlan>("suggest_network_ports", {
    request: {
      profiles: selectedProfiles(),
      installDir: input("install-dir").value.trim(),
    },
  });
  applyNetworkPortPlan(plan);
  autoAssignedPortsDeploymentId = bootstrapValidation?.deploymentId ?? null;
  invalidateFrom(3);
  if (showConfirmation) {
    showStepError(
      `Puertos libres asignados: GPS/DVR ${plan.telemetryPort}, HT ${plan.radioControlPort}, Prometheus ${plan.prometheusPort}, Grafana ${plan.grafanaPort}, TURN ${plan.turnPort}/${plan.turnMinPort}-${plan.turnMaxPort}, LiveKit ${plan.livekitHttpPort}/${plan.livekitRtcTcpPort}/${plan.livekitUdpMinPort}-${plan.livekitUdpMaxPort}.`,
    );
  }
}

function applyNetworkModeDefaults(prefix: "" | "config-"): void {
  const mode = input(`${prefix}network-mode`).value as NetworkMode;
  const bindAddress = input(`${prefix}bind-address`);
  const publicBaseUrl = input(`${prefix}public-base-url`);
  if (mode === "local_only") {
    bindAddress.value = "127.0.0.1";
    publicBaseUrl.value = "http://127.0.0.1";
  } else if (mode === "trusted_lan") {
    bindAddress.value = "0.0.0.0";
    publicBaseUrl.value = system.suggestedPublicBaseUrl;
  } else if (/^https?:\/\/(?:127\.0\.0\.1|localhost)(?::|\/|$)/i.test(publicBaseUrl.value)) {
    bindAddress.value = "0.0.0.0";
    publicBaseUrl.value = "";
  }
  const help = document.querySelector<HTMLElement>(`#${prefix}network-mode-help`);
  if (help) help.textContent = networkModeDescription(mode);
  if (prefix === "config-" && publicBaseUrl.value) {
    for (const [endpointId, portId] of [
      ["config-telemetry-ingress-public-url", "config-telemetry-port"],
      ["config-telemetry-read-public-url", "config-telemetry-port"],
      ["config-metrics-public-url", "config-prometheus-port"],
      ["config-radio-control-public-url", "config-radio-control-port"],
    ]) {
      input(endpointId).value = endpointFromBase(publicBaseUrl.value, input(portId).value);
    }
  }
}

function installRequest(): Record<string, unknown> {
  const preferredFallbackOrder = input("connectivity-fallback-order").value.split(",");
  const enabledFallbacks = new Set<string>();
  if (input("connectivity-direct-data-plane-fallback-enabled").checked) enabledFallbacks.add("direct_data_plane");
  if (input("connectivity-supabase-fallback-enabled").checked) enabledFallbacks.add("supabase");
  return {
    installDir: input("install-dir").value.trim(),
    bootstrapJws,
    profiles: selectedProfiles(),
    projectName: input("project-name").value.trim(),
    networkMode: input("network-mode").value,
    networkConfigurationDeferred,
    bindAddress: input("bind-address").value.trim(),
    publicBaseUrl: input("public-base-url").value.trim(),
    corsOrigins: input("cors-origins").value.trim(),
    telemetryPort: integerValue("telemetry-port"),
    radioControlPort: integerValue("radio-control-port"),
    prometheusPort: integerValue("prometheus-port"),
    grafanaPort: integerValue("grafana-port"),
    turnRealm: input("turn-realm").value.trim(),
    turnExternalIp: input("turn-external-ip").value.trim(),
    turnPort: integerValue("turn-port"),
    turnTlsPort: integerValue("turn-tls-port"),
    turnMinPort: integerValue("turn-min-port"),
    turnMaxPort: integerValue("turn-max-port"),
    livekitNodeIp: input("livekit-node-ip").value.trim(),
    livekitPublicUrl: input("livekit-public-url").value.trim(),
    livekitHttpPort: integerValue("livekit-http-port"),
    livekitRtcTcpPort: integerValue("livekit-rtc-tcp-port"),
    livekitUdpMinPort: integerValue("livekit-udp-min-port"),
    livekitUdpMaxPort: integerValue("livekit-udp-max-port"),
    connectivityEdgeControlUrl: input("connectivity-edge-control-url").value.trim(),
    connectivityEdgeEnrollmentToken: input("connectivity-edge-enrollment-token").value.trim(),
    connectivityInternalRelayToken: input("connectivity-internal-relay-token").value.trim(),
    connectivityNodeRole: input("connectivity-node-role").value,
    connectivityNodePriority: integerValue("connectivity-node-priority"),
    connectivityPullLimit: integerValue("connectivity-pull-limit"),
    connectivityDirectDataPlaneFallbackEnabled: input("connectivity-direct-data-plane-fallback-enabled").checked,
    connectivitySupabaseFallbackEnabled: input("connectivity-supabase-fallback-enabled").checked,
    connectivityFallbackOrder: preferredFallbackOrder.filter((item) => enabledFallbacks.has(item)),
    usePublishedImages: input("published-images").checked,
    prepareOnly: input("prepare-only").checked,
  };
}

async function applyInstallation(): Promise<void> {
  setBusy(true);
  try {
    const result = await invoke<ActionResult>("apply_installation", { request: installRequest() });
    managedNodes = await invoke<ManagedNode[]>("list_managed_nodes");
    managerResult = { message: result.message, output: result.output, error: false };
    viewMode = "manager";
    render();
  } catch (error) {
    showResult("La instalación no pudo completarse", String(error), true);
  } finally {
    setBusy(false);
  }
}

async function promoteArchivedNode(index: number): Promise<void> {
  const node = managedNodes[index];
  if (!node || !node.operational || !node.archived) return;
  busy = true;
  render();
  try {
    const result = await invoke<ActionResult>("promote_archived_node", {
      request: { installDir: node.installDir },
    });
    managedNodes = await invoke<ManagedNode[]>("list_managed_nodes");
    managerResult = { message: result.message, output: result.output, error: false };
  } catch (error) {
    managedNodes = await invoke<ManagedNode[]>("list_managed_nodes").catch(() => managedNodes);
    managerResult = {
      message: "No se pudo promover el nodo",
      output: String(error),
      error: true,
    };
  } finally {
    busy = false;
    render();
  }
}

async function archiveIncompletePreparation(): Promise<void> {
  const installDir = input("install-dir").value.trim();
  setBusy(true);
  try {
    const result = await invoke<ActionResult>("archive_incomplete_preparation", {
      request: { installDir, bootstrapJws },
    });
    installation = await invoke<InstallationState>("inspect_installation", { request: { installDir } });
    validatedSteps = [validatedSteps[0], false, false, false, false];
    activeStep = 1;
    render();
    showStepError(`${result.message} ${result.output}`.trim());
  } catch (error) {
    showStepError(`No se pudo recuperar el destino: ${String(error)}`);
  } finally {
    setBusy(false);
    updateNavigationState();
  }
}

async function runNodeAction(action: string): Promise<void> {
  setBusy(true);
  try {
    const result = await invoke<ActionResult>("node_operation", {
      request: { installDir: input("install-dir").value.trim(), action },
    });
    showResult(result.message, result.output);
  } catch (error) {
    showResult(`No se pudo ejecutar ${action}`, String(error), true);
  } finally {
    setBusy(false);
  }
}

async function refreshManagedNodes(message?: string): Promise<void> {
  busy = true;
  render();
  try {
    system = await invoke<SystemInfo>("get_system_info");
    managedNodes = await invoke<ManagedNode[]>("list_managed_nodes");
    if (message) managerResult = { message, output: "Inventario local y estado Docker actualizados.", error: false };
  } catch (error) {
    managerResult = { message: "No se pudo actualizar el inventario", output: String(error), error: true };
  } finally {
    busy = false;
    render();
  }
}

async function runManagedNodeAction(index: number, action: string): Promise<void> {
  const node = managedNodes[index];
  if (!node) return;
  busy = true;
  managerResult = { message: `${actionLabels[action] ?? action}: ${node.displayName}`, output: "Operación en curso…", error: false };
  render();
  try {
    const result = await invoke<ActionResult>("node_operation", {
      request: { installDir: node.installDir, action },
    });
    managedNodes = await invoke<ManagedNode[]>("list_managed_nodes");
    managerResult = { message: result.message, output: result.output, error: false };
  } catch (error) {
    managedNodes = await invoke<ManagedNode[]>("list_managed_nodes").catch(() => managedNodes);
    managerResult = { message: `No se pudo ejecutar ${actionLabels[action] ?? action}`, output: String(error), error: true };
  } finally {
    busy = false;
    render();
  }
}

async function openWizardForNode(index: number): Promise<void> {
  const node = managedNodes[index];
  if (!node) return;
  busy = true;
  render();
  try {
    installation = await invoke<InstallationState>("inspect_installation", {
      request: { installDir: node.installDir },
    });
    system.defaultInstallDir = node.installDir;
    bootstrapJws = "";
    bootstrapValidation = null;
    wizardTargetPinned = true;
    networkConfigurationDeferred = false;
    validatedSteps = [system.dockerCli && system.composeV2 && system.dockerDaemon, false, false, false, false];
    activeStep = 1;
    viewMode = "wizard";
  } catch (error) {
    managerResult = { message: "No se pudo abrir el nodo", output: String(error), error: true };
  } finally {
    busy = false;
    render();
  }
}

async function openConfigurationForNode(index: number): Promise<void> {
  const node = managedNodes[index];
  if (!node || !node.operational || node.archived) return;
  busy = true;
  render();
  try {
    installation = await invoke<InstallationState>("inspect_installation", {
      request: { installDir: node.installDir },
    });
    managerResult = null;
    configurationNodeIndex = index;
    viewMode = "configuration";
  } catch (error) {
    managerResult = { message: "No se pudo abrir la configuración", output: String(error), error: true };
  } finally {
    busy = false;
    render();
  }
}

function stopAuditPolling(): void {
  if (auditRefreshTimer != null) {
    window.clearTimeout(auditRefreshTimer);
    auditRefreshTimer = null;
  }
}

function scheduleAuditRefresh(): void {
  stopAuditPolling();
  if (viewMode !== "audit" || auditNodeIndex == null) return;
  auditRefreshTimer = window.setTimeout(() => void refreshNodeAudit(), 3_000);
}

async function refreshNodeAudit(): Promise<void> {
  if (auditRefreshInProgress || viewMode !== "audit" || auditNodeIndex == null) return;
  const node = managedNodes[auditNodeIndex];
  if (!node) return;
  stopAuditPolling();
  auditRefreshInProgress = true;
  if (!auditSnapshot) render();
  try {
    auditSnapshot = await invoke<NodeAuditSnapshot>("audit_node_telemetry", {
      request: { installDir: node.installDir },
    });
    auditError = auditSnapshot.databaseError || null;
  } catch (error) {
    auditError = String(error);
  } finally {
    auditRefreshInProgress = false;
    if (viewMode === "audit") {
      const scrollY = window.scrollY;
      render();
      window.requestAnimationFrame(() => window.scrollTo({ top: scrollY }));
      scheduleAuditRefresh();
    }
  }
}

async function openAuditForNode(index: number): Promise<void> {
  const node = managedNodes[index];
  if (!node || !node.operational || node.archived || !node.profiles.includes("telemetry")) return;
  stopAuditPolling();
  auditNodeIndex = index;
  auditSnapshot = null;
  auditError = null;
  auditTab = "gps";
  viewMode = "audit";
  render();
  await refreshNodeAudit();
}

function bindAuditEvents(): void {
  document.querySelector("#back-from-audit")?.addEventListener("click", () => {
    stopAuditPolling();
    auditNodeIndex = null;
    auditSnapshot = null;
    auditError = null;
    viewMode = "manager";
    render();
  });
  document.querySelector("#refresh-audit")?.addEventListener("click", () => void refreshNodeAudit());
  document.querySelectorAll<HTMLButtonElement>("[data-audit-tab]").forEach((button) => {
    button.addEventListener("click", () => {
      auditTab = button.dataset.auditTab === "dvr" ? "dvr" : "gps";
      render();
    });
  });
}

function nodeConfigurationRequest(): Record<string, unknown> {
  const preferredFallbackOrder = input("config-connectivity-fallback-order").value.split(",");
  const enabledFallbacks = new Set<string>();
  if (input("config-connectivity-direct-data-plane-fallback-enabled").checked) enabledFallbacks.add("direct_data_plane");
  if (input("config-connectivity-supabase-fallback-enabled").checked) enabledFallbacks.add("supabase");
  return {
    installDir: configurationNodeIndex == null ? "" : managedNodes[configurationNodeIndex]?.installDir ?? "",
    networkMode: input("config-network-mode").value,
    bindAddress: input("config-bind-address").value.trim(),
    publicBaseUrl: input("config-public-base-url").value.trim(),
    corsOrigins: input("config-cors-origins").value.trim(),
    telemetryIngressPublicUrl: input("config-telemetry-ingress-public-url").value.trim(),
    telemetryReadPublicUrl: input("config-telemetry-read-public-url").value.trim(),
    metricsPublicUrl: input("config-metrics-public-url").value.trim(),
    radioControlPublicUrl: input("config-radio-control-public-url").value.trim(),
    turnUrls: input("config-turn-urls").value.trim(),
    telemetryPort: integerValue("config-telemetry-port"),
    radioControlPort: integerValue("config-radio-control-port"),
    prometheusPort: integerValue("config-prometheus-port"),
    grafanaPort: integerValue("config-grafana-port"),
    turnRealm: input("config-turn-realm").value.trim(),
    turnExternalIp: input("config-turn-external-ip").value.trim(),
    turnPort: integerValue("config-turn-port"),
    turnTlsPort: integerValue("config-turn-tls-port"),
    turnMinPort: integerValue("config-turn-min-port"),
    turnMaxPort: integerValue("config-turn-max-port"),
    livekitNodeIp: input("config-livekit-node-ip").value.trim(),
    livekitPublicUrl: input("config-livekit-public-url").value.trim(),
    livekitHttpPort: integerValue("config-livekit-http-port"),
    livekitRtcTcpPort: integerValue("config-livekit-rtc-tcp-port"),
    livekitUdpMinPort: integerValue("config-livekit-udp-min-port"),
    livekitUdpMaxPort: integerValue("config-livekit-udp-max-port"),
    connectivityEdgeControlUrl: input("config-connectivity-edge-control-url").value.trim(),
    connectivityEdgeEnrollmentToken: input("config-connectivity-edge-enrollment-token").value.trim(),
    connectivityInternalRelayToken: input("config-connectivity-internal-relay-token").value.trim(),
    connectivityNodeRole: input("config-connectivity-node-role").value,
    connectivityNodePriority: integerValue("config-connectivity-node-priority"),
    connectivityPullLimit: integerValue("config-connectivity-pull-limit"),
    connectivityDirectDataPlaneFallbackEnabled: input("config-connectivity-direct-data-plane-fallback-enabled").checked,
    connectivitySupabaseFallbackEnabled: input("config-connectivity-supabase-fallback-enabled").checked,
    connectivityFallbackOrder: preferredFallbackOrder.filter((item) => enabledFallbacks.has(item)),
    usePublishedImages: input("config-published-images").checked,
    restartServices: input("config-restart-services").checked,
  };
}

function configuredBoolean(config: Record<string, string>, key: string, fallback: boolean): boolean {
  const value = config[key]?.trim().toLowerCase();
  return value === "true" ? true : value === "false" ? false : fallback;
}

function configuredInteger(config: Record<string, string>, key: string, fallback: number): number {
  const value = Number.parseInt(config[key] ?? "", 10);
  return Number.isSafeInteger(value) ? value : fallback;
}

function roamingEndpoint(
  config: Record<string, string>,
  key: string,
  portKey: string,
  fallbackPort: number,
  previousBaseUrl: string,
  nextBaseUrl: string,
): string {
  const current = config[key]?.trim() ?? "";
  const port = configuredInteger(config, portKey, fallbackPort);
  if (!current) return endpointFromBase(nextBaseUrl, String(port));
  try {
    const endpoint = new URL(current);
    const previousBase = new URL(previousBaseUrl);
    const endpointPort = endpoint.port || (endpoint.protocol === "https:" ? "443" : "80");
    if (
      endpoint.hostname === previousBase.hostname
      && endpointPort === String(port)
      && (endpoint.pathname === "/" || endpoint.pathname === "")
      && !endpoint.search
      && !endpoint.hash
    ) {
      return endpointFromBase(nextBaseUrl, String(port));
    }
  } catch {
    // La validación transaccional del backend informará cualquier valor legado inválido.
  }
  return current;
}

function trustedLanConfigurationRequest(
  node: ManagedNode,
  state: InstallationState,
  nextBaseUrl: string,
): Record<string, unknown> | null {
  const config = state.config;
  if (config.DATA_PLANE_NETWORK_MODE !== "trusted_lan") return null;
  const previousBaseUrl = (config.DATA_PLANE_PUBLIC_BASE_URL ?? "").replace(/\/$/, "");
  if (!previousBaseUrl || previousBaseUrl === nextBaseUrl.replace(/\/$/, "")) return null;

  const directFallbackEnabled = configuredBoolean(config, "CONNECTIVITY_DIRECT_DATA_PLANE_FALLBACK_ENABLED", true);
  const supabaseFallbackEnabled = configuredBoolean(config, "CONNECTIVITY_SUPABASE_FALLBACK_ENABLED", false);
  const enabledFallbacks = new Set([
    ...(directFallbackEnabled ? ["direct_data_plane"] : []),
    ...(supabaseFallbackEnabled ? ["supabase"] : []),
  ]);
  const configuredOrder = (config.CONNECTIVITY_FALLBACK_ORDER ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter((value) => enabledFallbacks.has(value));
  const fallbackOrder = configuredOrder.length === enabledFallbacks.size
    ? configuredOrder
    : [...enabledFallbacks];

  return {
    installDir: node.installDir,
    networkMode: "trusted_lan",
    bindAddress: "0.0.0.0",
    publicBaseUrl: nextBaseUrl,
    corsOrigins: config.DATA_PLANE_CORS_ORIGINS ?? "http://localhost:5173,http://tauri.localhost,https://localhost",
    telemetryIngressPublicUrl: roamingEndpoint(config, "TELEMETRY_INGRESS_PUBLIC_URL", "TELEMETRY_PORT", 8090, previousBaseUrl, nextBaseUrl),
    telemetryReadPublicUrl: roamingEndpoint(config, "TELEMETRY_READ_PUBLIC_URL", "TELEMETRY_PORT", 8090, previousBaseUrl, nextBaseUrl),
    metricsPublicUrl: roamingEndpoint(config, "METRICS_PUBLIC_URL", "PROMETHEUS_PORT", 9090, previousBaseUrl, nextBaseUrl),
    radioControlPublicUrl: roamingEndpoint(config, "RADIO_CONTROL_PUBLIC_URL", "RADIO_CONTROL_PORT", 8100, previousBaseUrl, nextBaseUrl),
    turnUrls: config.TURN_URLS ?? "",
    telemetryPort: configuredInteger(config, "TELEMETRY_PORT", 8090),
    radioControlPort: configuredInteger(config, "RADIO_CONTROL_PORT", 8100),
    prometheusPort: configuredInteger(config, "PROMETHEUS_PORT", 9090),
    grafanaPort: configuredInteger(config, "GRAFANA_PORT", 3001),
    turnRealm: config.TURN_REALM ?? "",
    turnExternalIp: config.TURN_EXTERNAL_IP ?? "",
    turnPort: configuredInteger(config, "TURN_PORT", 3478),
    turnTlsPort: configuredInteger(config, "TURN_TLS_PORT", 5349),
    turnMinPort: configuredInteger(config, "TURN_MIN_PORT", 49160),
    turnMaxPort: configuredInteger(config, "TURN_MAX_PORT", 49200),
    livekitNodeIp: config.LIVEKIT_NODE_IP ?? "",
    livekitPublicUrl: config.LIVEKIT_PUBLIC_URL ?? "",
    livekitHttpPort: configuredInteger(config, "LIVEKIT_HTTP_PORT", 7880),
    livekitRtcTcpPort: configuredInteger(config, "LIVEKIT_RTC_TCP_PORT", 7881),
    livekitUdpMinPort: configuredInteger(config, "LIVEKIT_UDP_MIN_PORT", 50000),
    livekitUdpMaxPort: configuredInteger(config, "LIVEKIT_UDP_MAX_PORT", 50100),
    connectivityEdgeControlUrl: config.CONNECTIVITY_EDGE_CONTROL_URL ?? "",
    connectivityEdgeEnrollmentToken: "",
    connectivityInternalRelayToken: "",
    connectivityNodeRole: config.CONNECTIVITY_NODE_ROLE === "primary" ? "primary" : "replica",
    connectivityNodePriority: configuredInteger(config, "CONNECTIVITY_NODE_PRIORITY", 100),
    connectivityPullLimit: configuredInteger(config, "CONNECTIVITY_PULL_LIMIT", 25),
    connectivityDirectDataPlaneFallbackEnabled: directFallbackEnabled,
    connectivitySupabaseFallbackEnabled: supabaseFallbackEnabled,
    connectivityFallbackOrder: fallbackOrder,
    usePublishedImages: config.ACTIUM_INSTALL_MODE === "published_images" || configuredBoolean(config, "ACTIUM_USE_PUBLISHED_IMAGES", false),
    restartServices: true,
  };
}

async function synchronizeTrustedLanNodes(): Promise<void> {
  if (trustedLanSyncInProgress || busy || viewMode !== "manager") return;
  trustedLanSyncInProgress = true;
  let applying = false;
  try {
    const latestSystem = await invoke<SystemInfo>("get_system_info");
    system = latestSystem;
    if (!latestSystem.dockerDaemon) return;
    const nextBaseUrl = latestSystem.suggestedPublicBaseUrl.replace(/\/$/, "");
    const suggestedHost = new URL(nextBaseUrl).hostname;
    if (suggestedHost === "127.0.0.1" || suggestedHost === "localhost") return;
    const synchronized: string[] = [];
    for (const node of managedNodes.filter((candidate) => candidate.operational && !candidate.archived)) {
      if (trustedLanSyncAttempts.get(node.key) === nextBaseUrl) continue;
      const state = await invoke<InstallationState>("inspect_installation", {
        request: { installDir: node.installDir },
      });
      const request = trustedLanConfigurationRequest(node, state, nextBaseUrl);
      if (!request) continue;
      trustedLanSyncAttempts.set(node.key, nextBaseUrl);
      if (!applying) {
        applying = true;
        busy = true;
        render();
      }
      await invoke<ActionResult>("update_node_configuration", { request });
      synchronized.push(node.displayName);
    }
    if (synchronized.length > 0) {
      managedNodes = await invoke<ManagedNode[]>("list_managed_nodes");
      managerResult = {
        message: "Cambio de LAN aplicado",
        output: `${synchronized.join(", ")} vuelve a publicar sus endpoints derivados desde ${nextBaseUrl}.`,
        error: false,
      };
      render();
    }
  } catch (error) {
    managerResult = {
      message: "La nueva LAN requiere revisión",
      output: `La sincronización automática no pudo aplicarse: ${String(error)}. Abra Configurar para revisar la política sin perder la anterior.`,
      error: true,
    };
    render();
  } finally {
    if (applying) {
      busy = false;
      render();
    }
    trustedLanSyncInProgress = false;
  }
}

async function saveNodeConfiguration(): Promise<void> {
  const index = configurationNodeIndex;
  if (index == null || !managedNodes[index]) return;
  const request = nodeConfigurationRequest();
  busy = true;
  render();
  try {
    const result = await invoke<ActionResult>("update_node_configuration", {
      request,
    });
    managedNodes = await invoke<ManagedNode[]>("list_managed_nodes");
    managerResult = { message: result.message, output: result.output, error: false };
    configurationNodeIndex = null;
    viewMode = "manager";
  } catch (error) {
    managerResult = { message: "No se pudo aplicar la configuración", output: String(error), error: true };
  } finally {
    busy = false;
    render();
  }
}

function addNode(): void {
  const separator = system.platform === "windows" ? "\\" : "/";
  system.defaultInstallDir = `${system.managedNodesDir}${separator}NuevoNodo`;
  installation = {
    installed: false,
    operational: false,
    managed: false,
    profiles: [],
    config: {},
    markerPath: "",
    recoverableIncompletePreparation: false,
  };
  bootstrapJws = "";
  bootstrapValidation = null;
  autoAssignedPortsDeploymentId = null;
  wizardTargetPinned = false;
  networkConfigurationDeferred = false;
  validatedSteps = [system.dockerCli && system.composeV2 && system.dockerDaemon, false, false, false, false];
  activeStep = 1;
  viewMode = "wizard";
  render();
}

function bindManagerEvents(): void {
  document.querySelector("#refresh-nodes")?.addEventListener("click", () => void refreshManagedNodes("Estado actualizado"));
  document.querySelector("#add-node")?.addEventListener("click", addNode);
  document.querySelectorAll<HTMLButtonElement>(".manager-action").forEach((button) => {
    button.addEventListener("click", () => void runManagedNodeAction(Number(button.dataset.nodeIndex), button.dataset.action ?? "status"));
  });
  document.querySelectorAll<HTMLButtonElement>(".open-wizard").forEach((button) => {
    button.addEventListener("click", () => void openWizardForNode(Number(button.dataset.nodeIndex)));
  });
  document.querySelectorAll<HTMLButtonElement>(".promote-node").forEach((button) => {
    button.addEventListener("click", () => void promoteArchivedNode(Number(button.dataset.nodeIndex)));
  });
  document.querySelectorAll<HTMLButtonElement>(".configure-node").forEach((button) => {
    button.addEventListener("click", () => void openConfigurationForNode(Number(button.dataset.nodeIndex)));
  });
  document.querySelectorAll<HTMLButtonElement>(".audit-node").forEach((button) => {
    button.addEventListener("click", () => void openAuditForNode(Number(button.dataset.nodeIndex)));
  });
}

function bindConfigurationEvents(): void {
  document.querySelector("#back-to-manager")?.addEventListener("click", () => {
    configurationNodeIndex = null;
    viewMode = "manager";
    render();
  });
  document.querySelector("#cancel-node-configuration")?.addEventListener("click", () => {
    configurationNodeIndex = null;
    viewMode = "manager";
    render();
  });
  document.querySelector("#config-network-mode")?.addEventListener("change", () => applyNetworkModeDefaults("config-"));
  document.querySelector("#config-public-base-url")?.addEventListener("change", () => {
    const mode = input("config-network-mode").value as NetworkMode;
    if (mode !== "stable_vpn") return;
    applyNetworkModeDefaults("config-");
  });
  document.querySelector("#config-connectivity-direct-data-plane-fallback-enabled")?.addEventListener("change", () => synchronizeFallbackOrder("config-"));
  document.querySelector("#config-connectivity-supabase-fallback-enabled")?.addEventListener("change", () => synchronizeFallbackOrder("config-"));
  document.querySelector("#config-assign-free-ports")?.addEventListener("click", async () => {
    setBusy(true);
    try {
      const plan = await invoke<NetworkPortPlan>("suggest_network_ports", {
        request: {
          profiles: installation.profiles,
          installDir: configurationNodeIndex == null
            ? ""
            : managedNodes[configurationNodeIndex]?.installDir ?? "",
        },
      });
      applyNetworkPortPlan(plan, "config-");
      managerResult = {
        message: "Puertos libres asignados",
        output: "Se actualizaron los puertos y únicamente los endpoints derivados. Revise los valores antes de guardar.",
        error: false,
      };
    } catch (error) {
      managerResult = { message: "No se pudieron asignar puertos libres", output: String(error), error: true };
    } finally {
      const result = document.querySelector<HTMLElement>("#configuration-result");
      if (result && managerResult) {
        result.className = `result ${managerResult.error ? "error" : "success"}`;
        result.innerHTML = `<strong>${escapeHtml(managerResult.message)}</strong><pre>${escapeHtml(managerResult.output)}</pre>`;
      }
      setBusy(false);
    }
  });
  document.querySelector("#save-node-configuration")?.addEventListener("click", () => void saveNodeConfiguration());
}

function bindEvents(): void {
  document.querySelectorAll<HTMLButtonElement>("[data-step]").forEach((button) => {
    button.addEventListener("click", () => {
      const target = Number(button.dataset.step);
      changeStep(target);
    });
  });
  document.querySelector("#previous")?.addEventListener("click", () => changeStep(activeStep - 1));
  document.querySelector("#next")?.addEventListener("click", () => void advanceTo(activeStep + 1));
  document.querySelector("#network-mode")?.addEventListener("change", () => {
    networkConfigurationDeferred = false;
    const deferred = document.querySelector<HTMLInputElement>("#defer-network-configuration");
    if (deferred) deferred.checked = false;
    document.querySelector("#wizard-network-fields")?.classList.remove("deferred");
    applyNetworkModeDefaults("");
    invalidateFrom(3);
  });
  document.querySelector("#defer-network-configuration")?.addEventListener("change", (event) => {
    networkConfigurationDeferred = (event.currentTarget as HTMLInputElement).checked;
    document.querySelector("#wizard-network-fields")?.classList.toggle("deferred", networkConfigurationDeferred);
    if (networkConfigurationDeferred && !hasOperationalInstallation()) {
      input("network-mode").value = "local_only";
      applyNetworkModeDefaults("");
    }
    invalidateFrom(3);
  });
  document.querySelector("#connectivity-direct-data-plane-fallback-enabled")?.addEventListener("change", () => synchronizeFallbackOrder(""));
  document.querySelector("#connectivity-supabase-fallback-enabled")?.addEventListener("change", () => synchronizeFallbackOrder(""));
  document.querySelector("#back-to-manager")?.addEventListener("click", () => {
    viewMode = "manager";
    render();
  });
  document.querySelector("#refresh-system")?.addEventListener("click", refreshSystem);
  document.querySelector("#inspect-installation")?.addEventListener("click", inspectInstallation);
  document.querySelector("#archive-incomplete-preparation")?.addEventListener("click", archiveIncompletePreparation);
  document.querySelector("#bootstrap-package")?.addEventListener("change", (event) => void loadBootstrap(event.currentTarget as HTMLInputElement));
  document.querySelector("#install-dir")?.addEventListener("input", () => {
    wizardTargetPinned = true;
    invalidateFrom(1);
  });
  document.querySelectorAll<HTMLInputElement>('input[name="profiles"]').forEach((checkbox) => checkbox.addEventListener("change", () => {
    autoAssignedPortsDeploymentId = null;
    invalidateFrom(2);
  }));
  document.querySelectorAll<HTMLInputElement>('[data-panel="3"] input').forEach((field) => {
    field.addEventListener("input", () => invalidateFrom(3));
    field.addEventListener("change", () => invalidateFrom(3));
  });
  document.querySelector("#select-all")?.addEventListener("click", () => {
    document.querySelectorAll<HTMLInputElement>('input[name="profiles"]:not(:disabled)').forEach((checkbox) => { checkbox.checked = true; });
    autoAssignedPortsDeploymentId = null;
    invalidateFrom(2);
  });
  document.querySelector("#assign-free-ports")?.addEventListener("click", async () => {
    setBusy(true);
    try {
      await assignAvailablePorts(true);
    } catch (error) {
      showStepError(`No se pudieron asignar puertos libres: ${String(error)}`);
    } finally {
      setBusy(false);
      updateNavigationState();
    }
  });
  document.querySelector("#install-dependencies")?.addEventListener("click", async () => {
    setBusy(true);
    try {
      const result = await invoke<ActionResult>("install_dependencies");
      system = await invoke<SystemInfo>("get_system_info");
      activeStep = 0;
      validatedSteps = [false, false, false, false, false];
      render();
      showStepError(`${result.message} ${result.output}`.trim());
    } catch (error) {
      activeStep = 0;
      validatedSteps = [false, false, false, false, false];
      render();
      showStepError(`No se pudieron instalar las dependencias: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  });
  document.querySelector("#apply-installation")?.addEventListener("click", applyInstallation);
  document.querySelectorAll<HTMLButtonElement>(".node-action").forEach((button) => {
    button.addEventListener("click", () => runNodeAction(button.dataset.action ?? "status"));
  });
  synchronizeFallbackOrder("");
}

async function start(): Promise<void> {
  try {
    system = await invoke<SystemInfo>("get_system_info");
    managedNodes = await invoke<ManagedNode[]>("list_managed_nodes");
    if (managedNodes.length > 0) {
      viewMode = "manager";
    } else {
      installation = await invoke<InstallationState>("inspect_installation", {
        request: { installDir: system.defaultInstallDir },
      });
      viewMode = "wizard";
    }
    render();
    void synchronizeTrustedLanNodes();
    window.setInterval(() => void synchronizeTrustedLanNodes(), 15_000);
  } catch (error) {
    app.innerHTML = `<div class="fatal"><h1>No se pudo iniciar el instalador</h1><pre>${escapeHtml(String(error))}</pre></div>`;
  }
}

void start();
