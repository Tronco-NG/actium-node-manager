import { invoke } from "@tauri-apps/api/core";
import { composeProjectName } from "./product";
import { effectiveProfiles, visiblePortFieldIds } from "./capability-surface";
import "./styles.css";

type SystemInfo = {
  productDisplayName: string;
  productChannel: "stable" | "lab";
  nodeManagerVersion: string;
  dataPlaneReleaseVersion: string;
  payloadSchemaVersion: number;
  siteRuntimeSchemaVersion: string;
  legacyProductAliases: string[];
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
  authorizedNodesRoot: string;
  defaultNetworkPorts: NetworkPortPlan;
  executionBackend: "supervisor";
  supervisorAvailable: boolean;
  supervisorCompatible: boolean;
  supervisorVersion?: string | null;
  nodeSupervisorVersion: string;
  supervisorRecoveredOperations: number;
  supervisorObservedProtocol?: number | null;
  supervisorRequiredProtocol: number;
  supervisorObservedFeatures: string[];
  supervisorRequiredFeatures: string[];
  supervisorCompatibilityReason: string;
  networkAddresses: NetworkAddress[];
};

type NetworkAddress = {
  interface: string;
  address: string;
  prefixLength: number;
  family: "inet" | "inet6";
  scope: string;
};

type NetworkReconciliationPolicy = "manual" | "reconcile_on_operation" | "auto_on_interface_change";

type InstallationState = {
  installed: boolean;
  operational: boolean;
  managed: boolean;
  version?: string;
  activeRelease?: string;
  releaseDigest?: string;
  payloadSchema?: number;
  promotionStatus?: string;
  profiles: string[];
  config: Record<string, string>;
  markerPath: string;
  status?: string;
  deploymentId?: string;
  deploymentCode?: string;
  installationId?: string;
  recoverableIncompletePreparation: boolean;
  lastError?: string;
  managerChannel?: string;
};

type ActionResult = {
  ok: boolean;
  message: string;
  output: string;
  installedProfiles: string[];
};

type RuntimeActionResult = {
  message: string;
  output: string;
  releaseVersion?: string | null;
};

type FabricIdentity = {
  fabricId: string;
  composeProject: string;
  networkName: string;
  hostId?: string | null;
};

type RuntimeUnitHealth = {
  runtimeUnitId: string;
  capability: string;
  composeProject: string;
  state: "ready" | "alive" | "commissioned" | "degraded";
  commissioned: boolean;
  totalServices: number;
  aliveServices: number;
  readyServices: number;
  failures: string[];
};

type RuntimeUnitInventory = {
  fabric: FabricIdentity;
  deploymentId: string;
  units: RuntimeUnitHealth[];
};

type ExportDiagnosticResult = {
  path: string;
  bytes: number;
};

type NodeOperationJob = {
  id: string;
  installDir: string;
  nodeKey: string;
  nodeLabel: string;
  terminalId?: string | null;
  action: string;
  state: "queued" | "running" | "interrupted" | "validating" | "staging" | "promoting" | "completed" | "failed" | "rolled_back" | "manual_intervention_required" | "cancelled";
  queuedAtUnixSeconds: number;
  startedAtUnixSeconds?: number | null;
  finishedAtUnixSeconds?: number | null;
  message: string;
  output: string;
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
  activeRelease?: string;
  releaseDigest?: string;
  payloadSchema?: number;
  promotionStatus?: string;
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
  terminalPlatform?: string | null;
  terminalRuntime?: string | null;
  terminalDeviceType?: string | null;
  terminalType?: string | null;
  terminalIsNative?: boolean | null;
  terminalClass?: "capacitor_mobile" | "non_mobile" | "unknown" | null;
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
  recentBatches?: Array<{
    batchId: string;
    receivedAt?: string | null;
    processedAt?: string | null;
    status?: "processing" | "processed" | "failed" | null;
    errorCode?: string | null;
    pointCount?: number | null;
    firstSequence?: number | null;
  }>;
  recentPoints?: Array<{
    sequence?: number | null;
    fixAt?: string | null;
    ingestedAt?: string | null;
    source?: string | null;
    appState?: string | null;
    provider?: string | null;
    accuracy?: number | null;
    latitude?: number | null;
    longitude?: number | null;
    dvrSessionId?: string | null;
  }>;
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

type NodeHtAuditFinding = {
  code: string;
  tone: "ok" | "warning" | "bad" | "info";
  title: string;
  detail: string;
  action: string;
};

type NodeHtAuditSnapshot = {
  generatedAt: string;
  projectName: string;
  services: NodeAuditService[];
  configuration: {
    profiles: string[];
    networkMode?: string | null;
    bindAddress?: string | null;
    publicBaseUrl: string;
    corsOriginCount: number;
    radioControlPublicUrl: string;
    radioControlPort?: string | null;
    endpointHostAligned: boolean;
    safEnabled: boolean;
    turnEnabled: boolean;
    turnUrlCount: number;
    turnRealm?: string | null;
    livekitEnabled: boolean;
    livekitPublicUrl: string;
    authorityBoundary: string;
  };
  runtime?: {
    generation?: number | null;
    checksum?: string | null;
    publicEndpoints?: Record<string, unknown> | null;
  } | null;
  runtimeError?: string | null;
  findings: NodeHtAuditFinding[];
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
  clientId?: string;
  organizationId?: string;
  siteId?: string;
  siteCode?: string;
  siteName?: string;
  siteCoreDeploymentId?: string;
  siteCoreEndpoint?: string;
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
  radioSafPort: number;
  siteCorePort: number;
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
  { id: "site-core", title: "Site Core soberano", scope: "Control local", description: "Bundle/LKG firmado, autoridad delegada, identidad operativa y bootstrap offline de Aegis Control.", ports: "8088/TCP" },
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
let viewMode: "manager" | "operations" | "wizard" | "configuration" | "audit" | "htAudit" | "runtimeUnits" = "wizard";
let managedNodes: ManagedNode[] = [];
let operationJobs: NodeOperationJob[] = [];
let selectedOperationJobId: string | null = null;
let operationPollTimer: number | null = null;
let operationSnapshot = "";
let operationUiSnapshot = "";
let terminalOperationSnapshot = "";
let routeResolution = 0;
let operationChatOpen = false;
let operationChatSelectedNodeKey: string | null = null;
let operationChatSelectedJobId: string | null = null;
let operationChatPreferredJobId: string | null = null;
let operationChatNodePage = 0;
let operationChatHistoryPage = 0;
let operationPage = 0;
let operationsFocusedJobId: string | null = null;
let operationsReturnRoute: string | null = null;
let restoreAuditAfterOperation = false;
let managerPage = 0;
let managerRefreshing = false;
let wizardTargetPinned = false;
let configurationNodeIndex: number | null = null;
let runtimeUnitsNodeIndex: number | null = null;
let runtimeUnitInventory: RuntimeUnitInventory | null = null;
let runtimeUnitBusyId: string | null = null;
let auditNodeIndex: number | null = null;
let auditSnapshot: NodeAuditSnapshot | null = null;
let auditError: string | null = null;
type AuditTab = "gps" | "dvr" | "support";
type AuditSection = "terminals" | "terminal" | "services";
type AuditRefreshScope = "all" | "terminal" | "gps" | "dvr" | "background";
type AuditEvidenceScope = "terminal" | "gps" | "dvr" | "services";

let auditTab: AuditTab = "gps";
let auditSection: AuditSection = "services";
let auditTerminalScope: "mobile" | "review" = "mobile";
let auditSelectedTerminalId: string | null = null;
let auditTerminalPage = 0;
let auditIssuePage = 0;
let auditSuggestionsOpen = false;
let auditEvidencePage = 0;
let auditEvidenceScope: AuditEvidenceScope = "terminal";
let auditSupportJobId: string | null = null;
let auditDiagnosticJobId: string | null = null;
let auditActionMessage: string | null = null;
let auditRefreshTimer: number | null = null;
let auditRefreshInProgress = false;
let auditRefreshScope: AuditRefreshScope | null = null;
let htAuditNodeIndex: number | null = null;
let htAuditSnapshot: NodeHtAuditSnapshot | null = null;
let htAuditError: string | null = null;
let htAuditMessage: string | null = null;
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

function redactDiagnosticText(value: string): string {
  return value
    .replace(/\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi, "Bearer [REDACTADO]")
    .replace(/\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g, "[JWT REDACTADO]")
    .replace(
      /(^|[\s,{])([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PRIVATE_KEY|API_KEY|ENROLLMENT)[A-Z0-9_]*)\s*[:=]\s*("[^"]*"|'[^']*'|[^\s,}]+)/gim,
      "$1$2=[REDACTADO]",
    )
    .replace(/([?&](?:token|secret|key|password|apikey)=)[^&\s]+/gi, "$1[REDACTADO]");
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
  if (mode === "trusted_lan") return "La publicación se conserva y se reconcilia antes de iniciar, reiniciar o actualizar el nodo. Los cambios automáticos de interfaz no se aplican sin una política explícita del host.";
  return "Conserva una URL/IP de VPN estable aunque cambie la Wi-Fi o el proveedor de acceso.";
}

function defaultNetworkAddress(): NetworkAddress | undefined {
  const isContainerInterface = (value: string): boolean => {
    const name = value.toLowerCase();
    return name === "docker0" || name === "podman0" || name === "cni0" || name === "virbr0"
      || name.startsWith("br-") || name.startsWith("veth") || name.startsWith("cni")
      || name.startsWith("flannel") || name.startsWith("cali");
  };
  const rank = (candidate: NetworkAddress): [number, number, number] => {
    const ipv4Global = candidate.family === "inet" && candidate.scope === "global";
    const global = candidate.scope === "global";
    const container = isContainerInterface(candidate.interface);
    return [
      ipv4Global && !container ? 0 : global && !container ? 1 : ipv4Global ? 2 : global ? 3 : 4,
      container ? 1 : 0,
      candidate.family === "inet" ? 0 : 1,
    ];
  };
  return [...system.networkAddresses].sort((left, right) => {
    const leftRank = rank(left);
    const rightRank = rank(right);
    return leftRank[0] - rightRank[0]
      || leftRank[1] - rightRank[1]
      || leftRank[2] - rightRank[2]
      || left.interface.localeCompare(right.interface)
      || left.address.localeCompare(right.address);
  })[0];
}

function networkPolicyOptions(selected: NetworkReconciliationPolicy): string {
  return [
    ["manual", "Manual"],
    ["reconcile_on_operation", "Antes de operar"],
    ["auto_on_interface_change", "Al cambiar interfaz"],
  ].map(([value, label]) => `<option value="${value}" ${selected === value ? "selected" : ""}>${label}</option>`).join("");
}

function networkInterfaceOptions(selected: string): string {
  const interfaces = [...new Set(system.networkAddresses.map((candidate) => candidate.interface))];
  return ["", ...interfaces]
    .map((value) => `<option value="${escapeHtml(value)}" ${selected === value ? "selected" : ""}>${escapeHtml(value || "Sin selección explícita")}</option>`)
    .join("");
}

function networkAddressOptions(selectedInterface: string, selectedAddress: string): string {
  const addresses = system.networkAddresses.filter((candidate) => !selectedInterface || candidate.interface === selectedInterface);
  return ["", ...addresses.map((candidate) => candidate.address)]
    .map((value) => `<option value="${escapeHtml(value)}" ${selectedAddress === value ? "selected" : ""}>${escapeHtml(value || "Sin selección explícita")}</option>`)
    .join("");
}

function refreshNetworkAddressOptions(prefix: "" | "config-"): void {
  const interfaceSelect = document.querySelector<HTMLSelectElement>(`#${prefix}network-interface`);
  const addressSelect = document.querySelector<HTMLSelectElement>(`#${prefix}network-address`);
  if (!interfaceSelect || !addressSelect) return;
  const current = addressSelect.value;
  addressSelect.innerHTML = networkAddressOptions(interfaceSelect.value, current);
  if (!addressSelect.value) {
    addressSelect.value = system.networkAddresses.find((candidate) => (
      candidate.interface === interfaceSelect.value && candidate.family === "inet" && candidate.scope === "global"
    ))?.address ?? "";
  }
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
    const installed = (hasOperationalInstallation() || installation.recoverableIncompletePreparation) && installation.profiles.includes(profile.id);
    const authorized = installed || bootstrapValidation?.profiles.includes(profile.id) === true;
    return `
      <label class="profile-card ${installed ? "installed" : ""} ${authorized ? "" : "unauthorized"}">
        <input type="checkbox" name="profiles" value="${profile.id}" ${installed ? "checked disabled" : authorized ? "" : "disabled"} />
        <span class="profile-check">✓</span>
        <span class="profile-copy">
          <span class="profile-kicker">${escapeHtml(profile.scope)}${installed ? (hasOperationalInstallation() ? " · instalado" : " · leftover") : authorized ? "" : " · no autorizado"}</span>
          <strong>${escapeHtml(profile.title)}</strong>
          <small>${escapeHtml(profile.description)}</small>
          <code>${escapeHtml(profile.ports)}</code>
        </span>
      </label>`;
  }).join("");
}

const actionLabels: Record<string, string> = {
  apply_configuration: "Aplicar configuración",
  save_configuration: "Guardar configuración",
  status: "Estado",
  verify: "Verificar",
  start: "Iniciar",
  stop: "Detener",
  restart: "Reiniciar",
  update: "Actualizar",
  logs: "Registros",
  diagnostics: "Diagnóstico completo",
  audit_terminal: "Actualizar terminal",
  audit_gps: "Actualizar GPS",
  audit_dvr: "Actualizar DVR",
  audit_ht: "Auditar HT",
  logs_ht: "Registros HT",
};

const jobStateLabels: Record<NodeOperationJob["state"], string> = {
  queued: "En cola",
  running: "En curso",
  interrupted: "Interrumpida",
  validating: "Validando",
  staging: "Preparando staging",
  promoting: "Promoviendo",
  completed: "Completada",
  failed: "Fallida",
  rolled_back: "Rollback completado",
  manual_intervention_required: "Intervencion manual requerida",
  cancelled: "Cancelada",
};

const activeJobStates = new Set<NodeOperationJob["state"]>(["queued", "running", "validating", "staging", "promoting"]);
const terminalJobStates = new Set<NodeOperationJob["state"]>(["interrupted", "completed", "failed", "rolled_back", "manual_intervention_required", "cancelled"]);
const isActiveJob = (job: NodeOperationJob): boolean => activeJobStates.has(job.state);
const isTerminalJob = (job: NodeOperationJob): boolean => terminalJobStates.has(job.state);

function activeOperationJobs(): NodeOperationJob[] {
  return operationJobs.filter(isActiveJob);
}

function activeNodeOperation(node: ManagedNode): NodeOperationJob | undefined {
  return operationJobs.find((job) => (
    (job.nodeKey === node.key || job.installDir.toLowerCase() === node.installDir.toLowerCase())
    && isActiveJob(job)
  ));
}

function queuedOperationPosition(job: NodeOperationJob): number {
  if (job.state !== "queued") return 0;
  return operationJobs
    .filter((candidate) => candidate.state === "queued")
    .reverse()
    .sort((left, right) => left.queuedAtUnixSeconds - right.queuedAtUnixSeconds)
    .findIndex((candidate) => candidate.id === job.id) + 1;
}

type ManagerArea = "dashboard" | "operations" | "audit" | "htAudit" | "configuration" | "runtimeUnits" | "none";

function managerSidebar(active: ManagerArea, node?: ManagedNode | null): string {
  const activeCount = activeOperationJobs().length;
  return `
    <aside class="manager-sidebar">
      <header class="sidebar-brand">
        <div class="brand-mark">A</div>
        <div class="sidebar-brand-copy">
          <span class="eyebrow">ACTIUM</span>
          <strong>${escapeHtml(system.productDisplayName)}</strong>
          <span class="channel-badge ${system.productChannel}">CANAL ${escapeHtml(system.productChannel.toUpperCase())}</span>
        </div>
      </header>
      <button id="toggle-manager-sidebar" class="sidebar-toggle" aria-label="Contraer navegación" title="Contraer navegación">‹</button>
      <nav class="sidebar-nav" aria-label="Navegación principal">
        <span class="sidebar-section-label">Gestión</span>
        <button class="${active === "dashboard" ? "active" : ""}" data-route="#/dashboard" title="Dashboard">
          <i aria-hidden="true">⌂</i><span>Dashboard</span>
        </button>
        <button class="${active === "operations" ? "active" : ""}" data-route="#/operations" title="Operaciones">
          <i aria-hidden="true">⇄</i><span>Operaciones</span>
          ${activeCount > 0 ? `<b>${activeCount}</b>` : ""}
        </button>
        <button data-route="#/nodes/new" title="Agregar nodo">
          <i aria-hidden="true">＋</i><span>Agregar nodo</span>
        </button>
        ${node ? `
          <span class="sidebar-section-label">Nodo actual</span>
          <div class="sidebar-node-context">
            <strong title="${escapeHtml(node.displayName)}">${escapeHtml(node.displayName)}</strong>
            <small>${escapeHtml(node.deploymentCode ?? node.projectName ?? node.version ?? "administrado")}</small>
          </div>
          ${node.profiles.includes("telemetry") ? `
            <button class="${active === "audit" ? "active" : ""}" data-route="${nodeRoute(node, "audit")}" title="Auditoría GPS/DVR">
              <i aria-hidden="true">◎</i><span>Auditoría GPS/DVR</span>
            </button>` : ""}
          ${node.profiles.some((profile) => profile.startsWith("radio-")) ? `
            <button class="${active === "htAudit" ? "active" : ""}" data-route="${nodeRoute(node, "audit-ht")}" title="Auditoría HT">
              <i aria-hidden="true">⌁</i><span>Auditoría HT</span>
            </button>` : ""}
          ${node.operational ? `<button class="${active === "configuration" ? "active" : ""}" data-route="${nodeRoute(node, "configuration")}" title="Configuración">
            <i aria-hidden="true">⚙</i><span>Configuración</span>
          </button>` : ""}
          ${system.executionBackend === "supervisor" ? `
            <button class="${active === "runtimeUnits" ? "active" : ""}" data-route="${nodeRoute(node, "runtime")}" title="Runtime units">
              <i aria-hidden="true">◫</i><span>Runtime units</span>
            </button>` : ""}` : ""}
      </nav>
      <footer class="sidebar-footer">
        <span class="${system.dockerDaemon ? "ok" : "bad"}"><i></i>${system.executionBackend === "supervisor" ? "Supervisor" : "Docker"} ${system.dockerDaemon ? "operativo" : "sin conexión"}</span>
        <small>Manager ${escapeHtml(system.nodeManagerVersion)}</small>
        ${system.executionBackend === "supervisor" ? `<small class="${system.supervisorCompatible ? "ok" : "bad"}">Supervisor ${escapeHtml(system.supervisorVersion ?? "ausente")} · proto ${system.supervisorObservedProtocol ?? "—"}/${system.supervisorRequiredProtocol}</small>` : ""}
        <small>Runtime ${escapeHtml(system.dataPlaneReleaseVersion)}</small>
      </footer>
    </aside>`;
}

function managerAppShell(
  active: ManagerArea,
  title: string,
  subtitle: string,
  content: string,
  node?: ManagedNode | null,
  actions = "",
): string {
  const sidebarCollapsed = localStorage.getItem("actium:manager-sidebar-collapsed") === "true";
  const contextOnly = title.length === 0;
  return `
    <div class="manager-app ${sidebarCollapsed ? "sidebar-collapsed" : ""}">
      ${managerSidebar(active, node)}
      <section class="manager-workspace">
        <header class="manager-pagebar ${contextOnly ? "context-only" : ""}">
          ${contextOnly ? "" : `<div class="manager-page-identity">
            <span class="eyebrow">ACTIUM CONTROL PLANE</span>
            <h1>${escapeHtml(title)}</h1>
            <small>${escapeHtml(subtitle)}</small>
          </div>`}
          <div class="manager-product-context">
            <span class="channel-badge ${system.productChannel}">CANAL ${escapeHtml(system.productChannel.toUpperCase())}</span>
            <small>Manager ${escapeHtml(system.nodeManagerVersion)} · ${system.executionBackend === "supervisor" ? `Supervisor ${escapeHtml(system.supervisorVersion ?? `${system.nodeSupervisorVersion} no disponible`)} · ` : ""}Runtime ${escapeHtml(system.dataPlaneReleaseVersion)} · Payload schema ${system.payloadSchemaVersion} · Site Runtime ${escapeHtml(system.siteRuntimeSchemaVersion)}</small>
          </div>
          ${actions ? `<div class="manager-page-actions">${actions}</div>` : ""}
        </header>
        ${system.executionBackend === "supervisor" && !system.supervisorCompatible ? `<div class="callout warning"><strong>Supervisor incompatible</strong><span>Observado proto ${system.supervisorObservedProtocol ?? "ausente"} / requerido ${system.supervisorRequiredProtocol}. Features obs [${(system.supervisorObservedFeatures ?? []).join(", ")}] req [${(system.supervisorRequiredFeatures ?? []).join(", ")}]. ${escapeHtml(system.supervisorCompatibilityReason ?? "")} Las operaciones privilegiadas permanecen bloqueadas.</span></div>` : ""}
        ${content}
      </section>
    </div>`;
}

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

function managerPageSize(): number {
  return window.innerWidth >= 1280 ? 3 : 2;
}

function nodeRoute(node: ManagedNode, destination: "configuration" | "audit" | "audit-ht" | "expand" | "runtime"): string {
  return `#/nodes/${encodeURIComponent(node.key)}/${destination}`;
}

function renderNodeCard(node: ManagedNode, index: number): string {
  const state = managerNodeState(node);
  const operation = activeNodeOperation(node);
  const queuePosition = operation ? queuedOperationPosition(operation) : 0;
  const serviceSummary = node.totalServices > 0
    ? `${node.runningServices}/${node.totalServices}`
    : node.operational ? "0 activos" : "No disponible";
  const profiles = node.profiles.join(", ") || "sin perfiles";
  const quickActions = node.canManage
    ? ["start", "stop", "update"].map((action) => {
      const duplicate = operationJobs.some((job) => (
        (job.nodeKey === node.key || job.installDir.toLowerCase() === node.installDir.toLowerCase())
        && job.action === action
        && isActiveJob(job)
      ));
      return `<button class="secondary compact manager-action" data-node-index="${index}" data-action="${action}" ${duplicate ? "disabled" : ""}>${actionLabels[action]}</button>`;
    }).join("")
    : "";
  return `
    <article class="node-card ${node.archived ? "archived" : ""}">
      <div class="node-card-head">
        <div class="node-identity">
          <span class="eyebrow">${escapeHtml(node.deploymentCode ?? node.projectName ?? "IDENTIDAD RECUPERABLE")}</span>
          <h3>${escapeHtml(node.displayName)}</h3>
        </div>
        <span class="manager-status ${state.tone}">${escapeHtml(state.label)}</span>
      </div>
      ${operation ? `
        <button class="node-operation-banner ${operation.state}" data-operation-job-id="${escapeHtml(operation.id)}">
          <span class="operation-pulse"></span>
          <strong>${escapeHtml(actionLabels[operation.action] ?? operation.action)}</strong>
          <small>${operation.state === "queued" ? `en cola${queuePosition > 0 ? ` · posición ${queuePosition}` : ""}` : jobStateLabels[operation.state]}</small>
        </button>` : ""}
      <dl class="node-facts">
        <div><dt>Versión</dt><dd>${escapeHtml(node.version ?? "legacy")}</dd></div>
        <div><dt>Release</dt><dd>${escapeHtml(node.activeRelease ?? "layout legacy")}</dd></div>
        <div><dt>Promoción</dt><dd>${escapeHtml(node.promotionStatus ?? "no transaccional")}</dd></div>
        <div><dt>Docker</dt><dd>${escapeHtml(serviceSummary)}</dd></div>
        <div class="wide"><dt>Perfiles</dt><dd title="${escapeHtml(profiles)}">${escapeHtml(profiles)}</dd></div>
        ${node.profiles.includes("connectivity") ? `
          <div><dt>Edge</dt><dd>${node.connectivityConfigured ? "Configurado" : "Pendiente"}</dd></div>
          <div><dt>Recuperación</dt><dd>${escapeHtml(node.connectivityNodeRole ?? "replica")} · p${node.connectivityNodePriority ?? 100}</dd></div>
          <div class="wide"><dt>Fallbacks</dt><dd>${escapeHtml(node.connectivityFallbackOrder.join(" → ") || "direct_data_plane")}</dd></div>` : ""}
      </dl>
      <code class="node-path" title="${escapeHtml(node.installDir)}">${escapeHtml(node.installDir)}</code>
      ${node.lastError ? `<div class="node-error">Último error: ${escapeHtml(node.lastError)}</div>` : ""}
      <div class="node-card-footer">
        <div class="node-quick-actions">${quickActions}</div>
        <details class="node-more">
          <summary>Más</summary>
          <div class="node-more-menu">
            ${node.canManage ? ["status", "verify", "restart", "logs"]
              .map((action) => `<button class="manager-action" data-node-index="${index}" data-action="${action}">${actionLabels[action]}</button>`)
              .join("") : ""}
            ${node.operational && !node.archived && node.profiles.includes("telemetry")
              ? `<button data-route="${nodeRoute(node, "audit")}">Auditoría GPS/DVR</button>` : ""}
            ${node.operational && !node.archived && node.profiles.some((profile) => profile.startsWith("radio-"))
              ? `<button data-route="${nodeRoute(node, "audit-ht")}">Auditoría HT</button>` : ""}
            ${node.operational && !node.archived
              ? `<button data-route="${nodeRoute(node, "configuration")}">Configurar nodo</button>` : ""}
            ${node.operational && system.executionBackend === "supervisor"
              ? `<button data-route="${nodeRoute(node, "runtime")}">Runtime units</button>` : ""}
            ${node.operational && node.archived
              ? `<button class="promote-node" data-node-index="${index}">Promover nodo</button>`
              : `<button data-route="${nodeRoute(node, "expand")}">${node.operational ? "Ampliar con .adpe" : node.recoverable ? "Reintentar con .adpe" : "Recuperar con .adpe"}</button>`}
          </div>
        </details>
      </div>
    </article>`;
}

function renderOperationChat(dashboardMessage: string): string {
  const activeJobs = activeOperationJobs();
  if (operationChatSelectedJobId && !operationJobs.some((job) => job.id === operationChatSelectedJobId)) {
    operationChatSelectedJobId = null;
  }
  const groups = new Map<string, { label: string; jobs: NodeOperationJob[] }>();
  for (const node of managedNodes) {
    groups.set(node.key, { label: node.displayName, jobs: [] });
  }
  for (const job of operationJobs) {
    const key = job.nodeKey || job.installDir.toLowerCase();
    const group = groups.get(key) ?? { label: job.nodeLabel, jobs: [] };
    group.jobs.push(job);
    groups.set(key, group);
  }
  if (operationChatSelectedNodeKey && !groups.has(operationChatSelectedNodeKey)) {
    operationChatSelectedNodeKey = null;
    operationChatHistoryPage = 0;
  }
  const running = activeJobs.find((job) => job.state !== "queued");
  const queued = activeJobs.filter((job) => job.state === "queued").length;
  const tone = running ? "running" : activeJobs.length > 0 ? "queued" : managerResult?.error ? "failed" : "";
  const nodeEntries = Array.from(groups.entries()).sort(([, left], [, right]) => {
    const leftActive = left.jobs.filter(isActiveJob).length;
    const rightActive = right.jobs.filter(isActiveJob).length;
    if (leftActive !== rightActive) return rightActive - leftActive;
    const leftLatest = left.jobs[0]?.queuedAtUnixSeconds ?? 0;
    const rightLatest = right.jobs[0]?.queuedAtUnixSeconds ?? 0;
    return rightLatest - leftLatest || left.label.localeCompare(right.label);
  });
  const nodePageSize = 4;
  const nodePageCount = Math.max(1, Math.ceil(nodeEntries.length / nodePageSize));
  operationChatNodePage = Math.min(operationChatNodePage, nodePageCount - 1);
  const nodePageStart = operationChatNodePage * nodePageSize;
  const visibleNodeEntries = nodeEntries.slice(nodePageStart, nodePageStart + nodePageSize);
  const selectedGroup = operationChatSelectedNodeKey ? groups.get(operationChatSelectedNodeKey) : null;
  const selectedChatJob = operationChatSelectedJobId
    ? operationJobs.find((job) => job.id === operationChatSelectedJobId) ?? null
    : null;
  const historyPageSize = 3;
  const historyPageCount = Math.max(1, Math.ceil((selectedGroup?.jobs.length ?? 0) / historyPageSize));
  operationChatHistoryPage = Math.min(operationChatHistoryPage, historyPageCount - 1);
  const historyPageStart = operationChatHistoryPage * historyPageSize;
  const visibleHistory = selectedGroup?.jobs.slice(historyPageStart, historyPageStart + historyPageSize) ?? [];
  const nodePicker = `
    <div class="operation-chat-node-picker">
      ${visibleNodeEntries.length > 0 ? visibleNodeEntries.map(([key, group]) => {
        const runningCount = group.jobs.filter((job) => isActiveJob(job) && job.state !== "queued").length;
        const queuedCount = group.jobs.filter((job) => job.state === "queued").length;
        const latest = group.jobs[0];
        const activity = runningCount > 0
          ? `${runningCount} en curso${queuedCount > 0 ? ` · ${queuedCount} en espera` : ""}`
          : queuedCount > 0
            ? `${queuedCount} ${queuedCount === 1 ? "en espera" : "en espera"}`
            : `${group.jobs.length} ${group.jobs.length === 1 ? "operación" : "operaciones"}`;
        return `
          <button class="operation-chat-node ${runningCount > 0 ? "running" : queuedCount > 0 ? "queued" : ""}" data-chat-node-key="${escapeHtml(key)}">
            <span class="operation-chat-avatar">${escapeHtml(group.label.slice(0, 1).toUpperCase() || "N")}</span>
            <span class="operation-chat-node-copy">
              <strong>${escapeHtml(group.label)}</strong>
              <small>${escapeHtml(activity)}</small>
            </span>
            <span class="operation-chat-node-latest">
              ${latest ? `${escapeHtml(actionLabels[latest.action] ?? latest.action)} · ${escapeHtml(jobStateLabels[latest.state])}` : "Sin actividad"}
            </span>
            <span class="operation-chat-node-arrow" aria-hidden="true">›</span>
          </button>`;
      }).join("") : `
        <div class="operation-chat-empty">
          <span class="operation-chat-avatar">A</span>
          <div>
            <strong>No hay nodos administrados</strong>
            <span>Al registrar el primer nodo aparecerá en esta bandeja.</span>
          </div>
        </div>`}
    </div>
    ${nodePageCount > 1 ? `
      <div class="operation-chat-pagination">
        <button id="previous-operation-chat-node-page" ${operationChatNodePage === 0 ? "disabled" : ""}>Anterior</button>
        <span>${operationChatNodePage + 1} / ${nodePageCount}</span>
        <button id="next-operation-chat-node-page" ${operationChatNodePage >= nodePageCount - 1 ? "disabled" : ""}>Siguiente</button>
      </div>` : ""}`;
  const nodeHistory = selectedGroup ? `
    <div class="operation-chat-history">
      ${visibleHistory.length > 0 ? visibleHistory.map((job) => {
        const queuePosition = queuedOperationPosition(job);
        const summary = job.state === "queued"
          ? `Esperando turno${queuePosition > 0 ? ` · posición ${queuePosition}` : ""}`
          : job.message;
        return `
          <button class="operation-chat-message ${job.state}" data-chat-job-id="${escapeHtml(job.id)}">
            <span class="operation-chat-message-head">
              <strong>${escapeHtml(actionLabels[job.action] ?? job.action)}</strong>
              <span class="job-state ${job.state}">${escapeHtml(jobStateLabels[job.state])}</span>
            </span>
            <span>${escapeHtml(summary)}</span>
            <small>${operationTime(job.queuedAtUnixSeconds)}${job.state === "queued" && queuePosition > 0 ? ` · #${queuePosition} de la cola` : ""}</small>
          </button>`;
      }).join("") : `
        <div class="operation-chat-empty">
          <span class="operation-chat-avatar">${escapeHtml(selectedGroup.label.slice(0, 1).toUpperCase() || "N")}</span>
          <div>
            <strong>Sin operaciones todavía</strong>
            <span>Las acciones de este nodo aparecerán aquí.</span>
          </div>
        </div>`}
    </div>
    ${historyPageCount > 1 ? `
      <div class="operation-chat-pagination">
        <button id="previous-operation-chat-history-page" ${operationChatHistoryPage === 0 ? "disabled" : ""}>Anterior</button>
        <span>${operationChatHistoryPage + 1} / ${historyPageCount}</span>
        <button id="next-operation-chat-history-page" ${operationChatHistoryPage >= historyPageCount - 1 ? "disabled" : ""}>Siguiente</button>
      </div>` : ""}` : "";
  const jobPreview = selectedChatJob ? `
    <div class="operation-chat-log-preview">
      <div class="operation-chat-log-summary">
        <span class="job-state ${selectedChatJob.state}">${escapeHtml(jobStateLabels[selectedChatJob.state])}</span>
        <strong>${escapeHtml(selectedChatJob.message)}</strong>
        <small>${operationTime(selectedChatJob.queuedAtUnixSeconds)} · ${operationDuration(selectedChatJob)}</small>
      </div>
      <pre>${escapeHtml(operationLogPreview(selectedChatJob))}</pre>
      <small class="operation-chat-preview-note">Vista previa acotada. Copiar incluye el registro completo y redactado.</small>
    </div>` : "";
  return `
    <div class="operation-chat ${operationChatOpen ? "open" : ""}">
      ${operationChatOpen ? `
        <aside class="operation-chat-panel" aria-label="Conversación del gestor de operaciones">
          <header class="operation-chat-panel-head">
            ${selectedChatJob || selectedGroup ? `<button id="back-operation-chat" class="operation-chat-back" aria-label="${selectedChatJob ? "Volver al historial del nodo" : "Volver a la lista de nodos"}">‹</button>` : ""}
            <div>
              <span class="eyebrow">GESTOR DE OPERACIONES</span>
              <strong>${selectedChatJob ? escapeHtml(actionLabels[selectedChatJob.action] ?? selectedChatJob.action) : selectedGroup ? escapeHtml(selectedGroup.label) : "Elegir nodo"}</strong>
              <small>${selectedChatJob ? escapeHtml(selectedChatJob.nodeLabel) : selectedGroup ? `${selectedGroup.jobs.length} ${selectedGroup.jobs.length === 1 ? "operación registrada" : "operaciones registradas"}` : `${running ? "1 en curso" : "Sin tareas en curso"} · ${queued} en espera`}</small>
            </div>
            <button id="close-operation-chat" class="operation-chat-close" aria-label="Cerrar cola">×</button>
          </header>
          <div class="operation-chat-body">
            <div class="operation-chat-intro">
              <strong>${selectedChatJob ? "Vista previa del registro" : selectedGroup ? "Historial de operaciones" : "¿Qué nodo querés revisar?"}</strong>
              <span>${selectedChatJob ? "Revise la salida antes de abandonar la auditoría." : selectedGroup ? "Seleccioná una operación para previsualizar y copiar su salida." : "Cada nodo conserva su cola y actividad separadas."}</span>
            </div>
            ${selectedChatJob ? jobPreview : selectedGroup ? nodeHistory : nodePicker}
          </div>
          ${selectedChatJob ? `
            <div class="operation-chat-detail-actions">
              <button id="copy-operation-chat-log" data-job-id="${escapeHtml(selectedChatJob.id)}">Copiar log</button>
              <button id="open-operation-chat-log" data-job-id="${escapeHtml(selectedChatJob.id)}">Abrir registro completo</button>
            </div>` : `
            <button class="operation-chat-detail" data-route="#/operations">
              Abrir centro de operaciones
              <span>Historial, salida completa y cancelación</span>
            </button>`}
        </aside>` : ""}
      <button id="toggle-operation-chat" class="operation-dock ${tone}" aria-expanded="${operationChatOpen}" title="${escapeHtml(dashboardMessage)}">
        <span class="operation-pulse"></span>
        <strong>GESTOR DE OPERACIONES</strong>
        <span class="operation-chat-chevron" aria-hidden="true">${operationChatOpen ? "⌄" : "⌃"}</span>
      </button>
    </div>`;
}

function renderManager(): void {
  const operational = managedNodes.filter((node) => node.operational && !node.archived).length;
  const recoverable = managedNodes.filter((node) => node.recoverable || node.archived).length;
  const pageSize = managerPageSize();
  const pageCount = Math.max(1, Math.ceil(managedNodes.length / pageSize));
  managerPage = Math.min(managerPage, pageCount - 1);
  const pageStart = managerPage * pageSize;
  const visibleNodes = managedNodes.slice(pageStart, pageStart + pageSize);
  const activeJobs = activeOperationJobs();
  const running = activeJobs.find((job) => job.state !== "queued");
  const dashboardMessage = running
    ? `${actionLabels[running.action] ?? running.action}: ${running.nodeLabel}`
    : activeJobs.length > 0
      ? `${activeJobs.length} ${activeJobs.length === 1 ? "operación pendiente" : "operaciones pendientes"}`
      : managerResult?.message ?? "Gestor listo";
  app.innerHTML = managerAppShell(
    "dashboard",
    "Dashboard de nodos",
    "Estado operativo, acciones rápidas y trabajos en segundo plano.",
    `<main class="manager-shell dashboard-shell">
      <section class="dashboard-summary">
        <div class="manager-metrics compact-metrics" aria-label="Resumen del gestor">
          <article><span>Administrables</span><strong>${operational}</strong></article>
          <article><span>Recuperables</span><strong>${recoverable}</strong></article>
          <article><span>Docker</span><strong>${system.dockerDaemon ? "Operativo" : "Sin conexión"}</strong></article>
        </div>
      </section>
      <section class="node-list dashboard-node-grid" style="--dashboard-columns: ${Math.max(1, visibleNodes.length)}">
        ${managedNodes.length === 0 ? `
          <div class="empty-manager">
            <strong>No se detectaron nodos todavía</strong>
            <span>Importe un paquete .adpe para registrar el primero.</span>
          </div>` : visibleNodes.map((node, offset) => renderNodeCard(node, pageStart + offset)).join("")}
      </section>
      <footer class="dashboard-footer">
        <div class="dashboard-pagination">
          <button id="previous-node-page" class="secondary compact" ${managerPage === 0 ? "disabled" : ""}>Anterior</button>
          <span>${managedNodes.length === 0 ? "Sin nodos" : `${pageStart + 1}–${Math.min(pageStart + pageSize, managedNodes.length)} de ${managedNodes.length}`}</span>
          <button id="next-node-page" class="secondary compact" ${managerPage >= pageCount - 1 ? "disabled" : ""}>Siguiente</button>
        </div>
        ${renderOperationChat(dashboardMessage)}
      </footer>
    </main>`,
    null,
    `<button id="refresh-nodes" class="secondary compact" ${managerRefreshing ? "disabled" : ""}>${managerRefreshing ? "Actualizando…" : "Actualizar estado"}</button>
     <button class="primary compact" data-route="#/nodes/new">Agregar nodo</button>`,
  );
  bindManagerEvents();
  bindRouteEvents();
}

function operationTime(value?: number | null): string {
  if (!value) return "—";
  return new Date(value * 1_000).toLocaleTimeString("es-AR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function operationDuration(job: NodeOperationJob): string {
  const start = job.startedAtUnixSeconds ?? job.queuedAtUnixSeconds;
  const end = job.finishedAtUnixSeconds ?? Math.floor(Date.now() / 1_000);
  const seconds = Math.max(0, end - start);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${seconds % 60}s`;
}

function operationLogText(job: NodeOperationJob): string {
  const output = job.output || (
    job.state === "queued"
      ? "Esperando su turno…"
      : isActiveJob(job)
        ? "La operación continúa en segundo plano…"
        : "Sin salida adicional."
  );
  return redactDiagnosticText([
    `${actionLabels[job.action] ?? job.action} · ${job.nodeLabel}`,
    `Estado: ${jobStateLabels[job.state]}`,
    `Encolada: ${operationTime(job.queuedAtUnixSeconds)}`,
    `Inicio: ${operationTime(job.startedAtUnixSeconds)}`,
    `Fin: ${operationTime(job.finishedAtUnixSeconds)}`,
    `Duración: ${operationDuration(job)}`,
    `Ruta: ${job.installDir}`,
    "",
    output,
  ].join("\n"));
}

function operationLogPreview(job: NodeOperationJob): string {
  const lines = operationLogText(job).split(/\r?\n/);
  const maximumLines = 12;
  const visibleLines = lines.length > maximumLines ? lines.slice(-maximumLines) : lines;
  const prefix = lines.length > maximumLines
    ? `… ${lines.length - maximumLines} líneas anteriores omitidas en la vista previa …\n`
    : "";
  return `${prefix}${visibleLines.join("\n")}`.slice(-5_000);
}

function operationReturnLabel(): string {
  if (operationsReturnRoute?.includes("/audit")) return "Volver a Auditoría GPS/DVR";
  if (operationsReturnRoute?.includes("/configuration")) return "Volver a Configuración";
  return "Volver";
}

function renderOperationJobDetail(job: NodeOperationJob | null): string {
  return `<article class="job-detail ${job?.state ?? "empty"}">
    ${job ? `
      <header>
        <div>
          <span class="job-state ${job.state}">${escapeHtml(jobStateLabels[job.state])}</span>
          <h3>${escapeHtml(actionLabels[job.action] ?? job.action)} · ${escapeHtml(job.nodeLabel)}</h3>
          <code>${escapeHtml(job.installDir)}</code>
        </div>
        <div class="job-detail-actions">
          <button id="copy-operation-log" class="secondary compact" data-job-id="${escapeHtml(job.id)}">Copiar log</button>
          ${job.state === "queued" ? `<button id="cancel-operation" class="secondary compact" data-job-id="${escapeHtml(job.id)}">Cancelar</button>` : ""}
        </div>
      </header>
      <dl class="job-timeline">
        <div><dt>Encolada</dt><dd>${operationTime(job.queuedAtUnixSeconds)}</dd></div>
        <div><dt>Inicio</dt><dd>${operationTime(job.startedAtUnixSeconds)}</dd></div>
        <div><dt>Fin</dt><dd>${operationTime(job.finishedAtUnixSeconds)}</dd></div>
        <div><dt>Duración</dt><dd>${operationDuration(job)}</dd></div>
      </dl>
      <strong class="job-message">${escapeHtml(job.message)}</strong>
      <pre>${escapeHtml(operationLogText(job))}</pre>` : `
      <div class="empty-manager">
        <strong>La operación ya no está disponible</strong>
        <span>La cola vive durante esta sesión. Vuelva al origen para continuar.</span>
      </div>`}
  </article>`;
}

function renderOperations(): void {
  const activeJobs = activeOperationJobs();
  const queued = activeJobs.filter((job) => job.state === "queued").length;
  const running = activeJobs.filter((job) => job.state === "running").length;
  const failed = operationJobs.filter((job) => job.state === "failed").length;
  const pageSize = window.innerHeight >= 900 ? 8 : 6;
  const pageCount = Math.max(1, Math.ceil(operationJobs.length / pageSize));
  operationPage = Math.min(Math.max(0, operationPage), pageCount - 1);
  const visibleJobs = operationJobs.slice(operationPage * pageSize, (operationPage + 1) * pageSize);
  if (!selectedOperationJobId || !operationJobs.some((job) => job.id === selectedOperationJobId)) {
    selectedOperationJobId = visibleJobs.find((job) => job.state === "running")?.id ?? visibleJobs[0]?.id ?? null;
  }
  const focused = operationsFocusedJobId != null;
  const selected = operationJobs.find((job) => job.id === (operationsFocusedJobId ?? selectedOperationJobId)) ?? null;
  app.innerHTML = managerAppShell(
    "operations",
    focused ? "Registro de operación" : "Cola de operaciones",
    focused
      ? selected
        ? `${actionLabels[selected.action] ?? selected.action} · ${selected.nodeLabel}`
        : "El registro solicitado ya no pertenece a esta sesión."
      : "Las tareas Docker se ejecutan en segundo plano; puede seguir navegando y encolar otros nodos.",
    `<main class="operations-shell">
      <section class="operations-layout ${focused ? "focused" : ""}">
        ${focused ? "" : `<div class="job-browser">
          <div class="job-list" role="list">
            ${operationJobs.length === 0 ? `
              <div class="empty-manager">
                <strong>No hay operaciones todavía</strong>
                <span>Ejecute una acción desde el Dashboard.</span>
              </div>` : visibleJobs.map((job) => `
                <button class="job-row ${job.id === selectedOperationJobId ? "selected" : ""}" data-job-id="${escapeHtml(job.id)}" role="listitem">
                  <span class="job-state ${job.state}">${escapeHtml(jobStateLabels[job.state])}</span>
                  <span class="job-row-copy">
                    <strong>${escapeHtml(actionLabels[job.action] ?? job.action)} · ${escapeHtml(job.nodeLabel)}</strong>
                    <small>${operationTime(job.queuedAtUnixSeconds)} · ${operationDuration(job)}</small>
                  </span>
                  ${job.state === "queued" ? `<span class="queue-position">#${queuedOperationPosition(job)}</span>` : ""}
                </button>`).join("")}
          </div>
          <footer class="operations-pagination">
            <button id="previous-operation-page" class="secondary compact" ${operationPage === 0 ? "disabled" : ""}>Anterior</button>
            <span>${operationJobs.length ? `${operationPage + 1} / ${pageCount}` : "0 / 0"}</span>
            <button id="next-operation-page" class="secondary compact" ${operationPage >= pageCount - 1 || operationJobs.length === 0 ? "disabled" : ""}>Siguiente</button>
          </footer>
        </div>`}
        ${renderOperationJobDetail(selected)}
      </section>
    </main>`,
    null,
    focused
      ? `<button id="back-from-operation-detail" class="secondary compact">${escapeHtml(operationReturnLabel())}</button>`
      : `<div class="operation-counters">
          <span><strong>${running}</strong> en curso</span>
          <span><strong>${queued}</strong> en cola</span>
          <span><strong>${failed}</strong> fallidas</span>
        </div>`,
  );
  bindOperationEvents();
  bindRouteEvents();
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

type AuditIssue = {
  id: string;
  tone: "warning" | "bad" | "neutral";
  title: string;
  detail: string;
  resolution: string;
  actions: Array<
    "logs"
    | "verify"
    | "restart"
    | "refresh"
    | "refresh-terminal"
    | "refresh-gps"
    | "refresh-dvr"
    | "support"
  >;
};

function auditTerminalKey(terminal: NodeTelemetryAudit): string {
  return `${terminal.organizationId}:${terminal.terminalId}`;
}

function auditTerminalName(terminal: NodeTelemetryAudit): string {
  const reported = terminal.terminalLabel?.trim();
  if (reported) return reported;
  return `${terminal.terminalClass === "capacitor_mobile" ? "Móvil" : "Terminal"} ${terminal.terminalId.slice(0, 8)}`;
}

function auditTerminalClassLabel(terminal: NodeTelemetryAudit): string {
  if (terminal.terminalClass === "capacitor_mobile") return "Capacitor móvil";
  if (terminal.terminalClass === "non_mobile") return "No compatible";
  return "Identidad por revisar";
}

function auditTerminalClassTone(terminal: NodeTelemetryAudit): "ok" | "warning" | "neutral" {
  if (terminal.terminalClass === "capacitor_mobile") return "ok";
  if (terminal.terminalClass === "non_mobile") return "neutral";
  return "warning";
}

const RECENT_LOCAL_TELEMETRY_MS = 10 * 60_000;

function auditTerminalTelemetryAt(terminal: NodeTelemetryAudit): string | null {
  const timestamps = [
    terminal.lastBatchProcessedAt,
    terminal.lastBatchReceivedAt,
    terminal.fixAt,
    terminal.dvrLastPointAt,
  ].filter((value): value is string => Boolean(value) && Number.isFinite(Date.parse(value!)));
  if (timestamps.length === 0) return null;
  return timestamps.reduce((latest, candidate) => (
    Date.parse(candidate) > Date.parse(latest) ? candidate : latest
  ));
}

function auditHasRecentLocalTelemetry(terminal: NodeTelemetryAudit): boolean {
  const observedAt = auditTerminalTelemetryAt(terminal);
  return Boolean(observedAt && Date.now() - Date.parse(observedAt) <= RECENT_LOCAL_TELEMETRY_MS);
}

function auditPresenceStage(terminal: NodeTelemetryAudit): {
  value: string;
  state: "ok" | "warning" | "bad" | "neutral";
  detail: string;
  inferredFromTelemetry: boolean;
} {
  if (terminal.presenceStatus === "online") {
    return {
      value: "online",
      state: "ok",
      detail: `${auditAge(terminal.heartbeatAt)} · ${terminal.appState || "estado desconocido"} · cola ${terminal.queueDepth ?? 0}`,
      inferredFromTelemetry: false,
    };
  }
  if (terminal.presenceStatus === "degraded") {
    return {
      value: "heartbeat degradado",
      state: "warning",
      detail: `${auditAge(terminal.heartbeatAt)} · ${terminal.appState || "estado desconocido"} · cola ${terminal.queueDepth ?? 0}`,
      inferredFromTelemetry: false,
    };
  }
  const telemetryAt = auditTerminalTelemetryAt(terminal);
  if (telemetryAt && auditHasRecentLocalTelemetry(terminal)) {
    return {
      value: "telemetría activa",
      state: "ok",
      detail: `GPS/lote local ${auditAge(telemetryAt)} · heartbeat no replicado al nodo`,
      inferredFromTelemetry: true,
    };
  }
  return {
    value: terminal.presenceStatus || "sin señal reciente",
    state: terminal.presenceStatus === "offline" ? "bad" : "neutral",
    detail: terminal.heartbeatAt
      ? `${auditAge(terminal.heartbeatAt)} · ${terminal.appState || "estado desconocido"} · cola ${terminal.queueDepth ?? 0}`
      : "Sin heartbeat local ni telemetría recibida durante los últimos 10 minutos.",
    inferredFromTelemetry: false,
  };
}

function renderGpsAuditTerminal(terminal: NodeTelemetryAudit, gatewayHealthy: boolean, projectorHealthy: boolean): string {
  const batchState = terminal.lastBatchStatus === "processed"
    ? "ok"
    : terminal.lastBatchStatus === "processing"
      ? "warning"
      : terminal.lastBatchStatus === "failed"
        ? "bad"
        : "neutral";
  const presence = auditPresenceStage(terminal);
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
  return `<div class="audit-pipeline">
      ${auditStage(
        "1 · Terminal / heartbeat",
        presence.value,
        presence.state,
        presence.detail,
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
    </div>`;
}

function renderDvrAuditTerminal(terminal: NodeTelemetryAudit, gatewayHealthy: boolean): string {
  const pointCount = Number(terminal.dvrPoints24h || 0);
  const dvrState = pointCount > 0 ? "ok" : terminal.lastBatchStatus === "failed" ? "bad" : "warning";
  return `<div class="audit-pipeline">
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
    </div>`;
}

function auditRefreshButton(scope: Exclude<AuditRefreshScope, "background">, label: string): string {
  const refreshing = auditRefreshInProgress
    && (auditRefreshScope === scope || auditRefreshScope === "all");
  return `<button class="secondary compact" data-audit-refresh-scope="${scope}" ${refreshing ? "disabled" : ""}>
    ${refreshing ? "Actualizando…" : escapeHtml(label)}
  </button>`;
}

function renderAuditPlane(
  scope: "gps" | "dvr",
  title: string,
  detail: string,
  pipeline: string,
): string {
  return `<div class="audit-plane-view">
    <header class="audit-plane-toolbar">
      <div>
        <span class="eyebrow">${scope === "gps" ? "ESTADO GPS" : "ESTADO DVR"}</span>
        <strong>${escapeHtml(title)}</strong>
        <small>${escapeHtml(detail)}</small>
      </div>
      <div class="button-row">
        ${auditRefreshButton(scope, `Actualizar ${scope.toUpperCase()}`)}
        <button class="secondary compact" data-audit-open-support="${scope}">Historial y soporte</button>
      </div>
    </header>
    ${pipeline}
  </div>`;
}

type AuditEvidenceItem = {
  id: string;
  at?: string | null;
  kind: "batch" | "point";
  tone: "ok" | "warning" | "bad" | "neutral";
  title: string;
  detail: string;
  meta: string;
};

function auditEvidenceItems(terminal: NodeTelemetryAudit, scope: Exclude<AuditEvidenceScope, "services">): AuditEvidenceItem[] {
  const batches = (terminal.recentBatches ?? []).map((batch): AuditEvidenceItem => ({
    id: `batch:${batch.batchId}`,
    at: batch.receivedAt,
    kind: "batch",
    tone: batch.status === "processed"
      ? "ok"
      : batch.status === "failed"
        ? "bad"
        : batch.status === "processing"
          ? "warning"
          : "neutral",
    title: `Lote ${batch.status || "sin estado"}`,
    detail: `${batch.pointCount ?? 0} puntos · secuencia ${batch.firstSequence ?? "s/d"}`,
    meta: batch.errorCode
      ? `${batch.batchId} · error ${batch.errorCode}`
      : `${batch.batchId} · procesado ${auditAge(batch.processedAt)}`,
  }));
  const points = (terminal.recentPoints ?? []).map((point): AuditEvidenceItem => {
    const dvrSession = point.dvrSessionId?.trim();
    const coordinates = Number.isFinite(point.latitude) && Number.isFinite(point.longitude)
      ? `${Number(point.latitude).toFixed(5)}, ${Number(point.longitude).toFixed(5)}`
      : "sin coordenadas";
    return {
      id: `point:${point.sequence ?? point.fixAt ?? point.ingestedAt ?? "unknown"}`,
      at: point.ingestedAt || point.fixAt,
      kind: "point",
      tone: scope === "dvr" && !dvrSession ? "warning" : "ok",
      title: scope === "dvr"
        ? dvrSession ? "Punto DVR etiquetado" : "Punto DVR sin sesión"
        : `Punto GPS #${point.sequence ?? "s/d"}`,
      detail: `${coordinates} · precisión ${point.accuracy ?? "s/d"}m`,
      meta: scope === "dvr"
        ? `${auditAge(point.fixAt)} · sesión ${dvrSession || "ausente"}`
        : `${auditAge(point.fixAt)} · ${point.source || "fuente desconocida"} · ${point.appState || "estado desconocido"}`,
    };
  });
  const items = scope === "gps" ? [...batches, ...points] : scope === "dvr" ? points : [...batches, ...points];
  return items.sort((left, right) => {
    const leftAt = left.at ? Date.parse(left.at) : 0;
    const rightAt = right.at ? Date.parse(right.at) : 0;
    return rightAt - leftAt;
  });
}

function auditServiceLogLines(): Array<{ id: string; tone: "ok" | "warning" | "bad" | "neutral"; text: string }> {
  const job = operationJobs.find((candidate) => candidate.id === auditSupportJobId);
  if (!job) return [];
  const raw = (job.output || job.message || "")
    .split(/\r?\n/)
    .map((line) => line.trimEnd())
    .filter((line) => line.trim().length > 0)
    .slice(-240)
    .reverse();
  if (raw.length === 0) {
    return [{
      id: `job:${job.id}`,
      tone: job.state === "failed" || job.state === "manual_intervention_required" ? "bad" : job.state === "completed" ? "ok" : "warning",
      text: `${jobStateLabels[job.state]} · ${job.message}`,
    }];
  }
  return raw.map((line, index) => {
    const safeLine = redactDiagnosticText(line);
    const normalized = safeLine.toLowerCase();
    return {
      id: `job:${job.id}:${index}`,
      tone: normalized.includes("error") || normalized.includes("failed") || normalized.includes("fatal")
        ? "bad"
        : normalized.includes("warn") || normalized.includes("pending") || normalized.includes("retry")
          ? "warning"
          : "neutral",
      text: safeLine,
    };
  });
}

function renderAuditEvidence(terminal: NodeTelemetryAudit): string {
  const pageSize = auditEvidenceScope === "services" ? 8 : 6;
  const evidence = auditEvidenceScope === "services"
    ? auditServiceLogLines()
    : auditEvidenceItems(terminal, auditEvidenceScope);
  const pages = Math.max(1, Math.ceil(evidence.length / pageSize));
  auditEvidencePage = Math.min(Math.max(0, auditEvidencePage), pages - 1);
  const visible = evidence.slice(auditEvidencePage * pageSize, (auditEvidencePage + 1) * pageSize);
  const supportJob = operationJobs.find((candidate) => candidate.id === auditSupportJobId);

  return `<section class="audit-evidence">
    <header>
      <div>
        <span class="eyebrow">EVIDENCIA OBSERVADA POR EL NODO</span>
        <strong>${auditEvidenceScope === "services" ? "Registros de servicios" : "Historial técnico"}</strong>
        <small>${auditEvidenceScope === "services"
          ? supportJob
            ? `${jobStateLabels[supportJob.state]} · ${supportJob.message}`
            : "Solicite Registros para cargar la salida de los contenedores."
          : "Lotes y puntos persistidos en PostgreSQL; no son logs internos del teléfono."}</small>
      </div>
      <div class="audit-evidence-tabs">
        ${(["terminal", "gps", "dvr", "services"] as AuditEvidenceScope[]).map((scope) => {
          const label = scope === "terminal" ? "Terminal" : scope === "services" ? "Servicios" : scope.toUpperCase();
          return `<button class="${auditEvidenceScope === scope ? "active" : ""}" data-audit-evidence-scope="${scope}">${label}</button>`;
        }).join("")}
      </div>
    </header>
    <div class="audit-evidence-list">
      ${visible.length === 0
        ? `<div class="audit-evidence-empty">
            <strong>${auditEvidenceScope === "services" ? "Registros todavía no solicitados" : "Sin evidencia para este plano"}</strong>
            <span>${auditEvidenceScope === "services"
              ? "Use “Registros del nodo” para ejecutar una captura sin seguimiento."
              : "Actualice este plano para consultar nuevamente el nodo."}</span>
          </div>`
        : visible.map((item) => "text" in item
          ? `<article class="audit-log-line ${item.tone}"><code>${escapeHtml(item.text)}</code></article>`
          : `<article class="audit-evidence-row ${item.tone}">
              <span>${item.kind === "batch" ? "LOTE" : "PUNTO"}</span>
              <div><strong>${escapeHtml(item.title)}</strong><small>${escapeHtml(item.detail)}</small></div>
              <code>${escapeHtml(item.meta)}</code>
            </article>`).join("")}
    </div>
    <footer class="audit-pagination">
      <button id="previous-audit-evidence-page" class="secondary compact" ${auditEvidencePage === 0 ? "disabled" : ""}>Anterior</button>
      <span>${evidence.length ? `${auditEvidencePage + 1} / ${pages}` : "0 / 0"}</span>
      <button id="next-audit-evidence-page" class="secondary compact" ${auditEvidencePage >= pages - 1 || evidence.length === 0 ? "disabled" : ""}>Siguiente</button>
    </footer>
  </section>`;
}

function currentAuditDiagnosticJob(): NodeOperationJob | null {
  return operationJobs.find((job) => job.id === auditDiagnosticJobId) ?? null;
}

function buildAuditDiagnosticReport(
  node: ManagedNode,
  terminal: NodeTelemetryAudit,
  issues: AuditIssue[],
): string {
  const nodeJobs = operationJobs
    .filter((job) => job.nodeKey === node.key || job.installDir.toLowerCase() === node.installDir.toLowerCase())
    .slice(0, 20)
    .map((job) => ({
      ...job,
      output: redactDiagnosticText(job.output).slice(-80_000),
    }));
  const payload = {
    schema: "actium-node-diagnostic/v1",
    generatedAt: new Date().toISOString(),
    manager: {
      product: system.productDisplayName,
      channel: system.productChannel,
      version: system.nodeManagerVersion,
      dataPlaneReleaseVersion: system.dataPlaneReleaseVersion,
      payloadSchemaVersion: system.payloadSchemaVersion,
      siteRuntimeSchemaVersion: system.siteRuntimeSchemaVersion,
      platform: system.platform,
      architecture: system.architecture,
      dockerCli: system.dockerCli,
      dockerDaemon: system.dockerDaemon,
      composeV2: system.composeV2,
    },
    node,
    selectedTerminal: terminal,
    currentIssues: issues,
    auditSnapshot,
    operations: nodeJobs,
  };
  return redactDiagnosticText([
    system.productDisplayName.toUpperCase(),
    "INFORME DIAGNÓSTICO COMPLETO",
    "Los secretos conocidos fueron redactados antes de copiar o exportar.",
    "",
    JSON.stringify(payload, null, 2),
  ].join("\n")).slice(0, 1_900_000);
}

function renderAuditSupport(terminal: NodeTelemetryAudit, node: ManagedNode): string {
  const diagnosticJob = currentAuditDiagnosticJob();
  const diagnosticReady = diagnosticJob != null && isTerminalJob(diagnosticJob) && diagnosticJob.state !== "cancelled";
  const diagnosticStatus = diagnosticJob
    ? `${jobStateLabels[diagnosticJob.state]} · ${diagnosticJob.message}`
    : "Aún no se reunió el paquete completo de estado, verificación y registros.";
  return `<div class="audit-support">
    <header class="audit-support-toolbar audit-support-commandbar">
      <div class="audit-support-report">
        <span class="eyebrow">INFORME Y ACCIONES</span>
        <strong>Informe completo · ${escapeHtml(node.displayName)}</strong>
        <small>${escapeHtml(diagnosticStatus)}</small>
      </div>
      <div class="audit-support-actions">
        <div class="audit-support-action-group" aria-label="Actualizar evidencia">
          ${auditRefreshButton("terminal", "Actualizar terminal")}
          ${auditRefreshButton("gps", "Actualizar GPS")}
          ${auditRefreshButton("dvr", "Actualizar DVR")}
        </div>
        <div class="audit-support-action-group diagnostic-actions" aria-label="Informe y diagnóstico">
          <button class="primary compact" data-audit-diagnostic="generate" ${diagnosticJob && isActiveJob(diagnosticJob) ? "disabled" : ""}>
            ${diagnosticJob && isActiveJob(diagnosticJob) ? "Reuniendo…" : "Generar informe"}
          </button>
          <button class="secondary compact" data-audit-diagnostic="copy" ${diagnosticReady ? "" : "disabled"}>Copiar</button>
          <button class="secondary compact" data-audit-diagnostic="export" ${diagnosticReady ? "" : "disabled"}>Exportar</button>
          <button class="secondary compact" data-audit-operation="verify">Verificar</button>
          <button class="secondary compact" data-audit-operation="logs">Registros</button>
        </div>
      </div>
    </header>
    <div class="audit-support-grid">
      ${renderAuditEvidence(terminal)}
    </div>
  </div>`;
}

function renderAuditSuggestionChat(issues: AuditIssue[]): string {
  const guidance = issues.filter((issue) => issue.tone !== "neutral");
  const criticalSuggestions = guidance.filter((issue) => issue.tone === "bad").length;
  const warningSuggestions = guidance.filter((issue) => issue.tone === "warning").length;
  const suggestionTone = criticalSuggestions > 0 ? "bad" : warningSuggestions > 0 ? "warning" : "ok";
  return `<div class="audit-suggestion-chat ${auditSuggestionsOpen ? "open" : ""}">
    ${auditSuggestionsOpen ? renderAuditSuggestionPanel(guidance) : ""}
    <button class="audit-suggestion-dock ${suggestionTone}" data-audit-suggestions-toggle aria-expanded="${auditSuggestionsOpen}">
      <span class="audit-suggestion-pulse" aria-hidden="true"></span>
      <span>
        <strong>Sugerencias de soporte</strong>
        <small>${guidance.length === 0
          ? "Sin recomendaciones pendientes"
          : `${guidance.length} para revisar · ${criticalSuggestions ? `${criticalSuggestions} crítica${criticalSuggestions === 1 ? "" : "s"}` : `${warningSuggestions} advertencia${warningSuggestions === 1 ? "" : "s"}`}`}</small>
      </span>
      <b>${auditSuggestionsOpen ? "Cerrar" : "Abrir"} ${auditSuggestionsOpen ? "⌄" : "⌃"}</b>
    </button>
  </div>`;
}

function auditServiceRow(
  label: string,
  value: string,
  state: "ok" | "warning" | "bad",
  detail: string,
): string {
  return `<article class="audit-service-row ${state}">
    <span class="audit-service-indicator" aria-hidden="true"></span>
    <strong>${escapeHtml(label)}</strong>
    <span>${escapeHtml(value)}</span>
    <code title="${escapeHtml(detail)}">${escapeHtml(detail)}</code>
  </article>`;
}

function renderAuditSectionNavigation(
  selectedTerminal: NodeTelemetryAudit | null,
  healthyServices: number,
  totalServices: number,
  unresolved: number,
  generatedAt: string,
): string {
  const terminalLabel = selectedTerminal ? auditTerminalName(selectedTerminal) : "Sin seleccionar";
  const infrastructureHealthy = healthyServices === totalServices && unresolved === 0;
  return `<div class="audit-context-bar">
    <nav class="audit-section-tabs" aria-label="Secciones de auditoría">
      <button class="${auditSection === "terminals" ? "active" : ""}" data-audit-section="terminals">
        Terminales
      </button>
      <button class="${auditSection === "terminal" ? "active" : ""}" data-audit-section="terminal" ${selectedTerminal ? "" : "disabled"}>
        ${escapeHtml(terminalLabel)}
      </button>
      <button class="${auditSection === "services" ? "active" : ""}" data-audit-section="services">
        Resumen del nodo
      </button>
    </nav>
    <div class="audit-context-actions">
      <span class="audit-updated">Corte ${escapeHtml(generatedAt)}</span>
      <button class="audit-health-summary ${infrastructureHealthy ? "ok" : "warning"}" data-audit-section="services" title="Abrir resumen operativo del nodo">
        <span><i></i>Componentes <strong>${healthyServices}/${totalServices}</strong></span>
        <span>Dead letters <strong>${unresolved}</strong></span>
        <b>Ver resumen ›</b>
      </button>
      ${auditRefreshButton("all", "Actualizar todo")}
    </div>
  </div>`;
}

function renderAuditTerminalSelector(
  visibleTerminals: NodeTelemetryAudit[],
  mobileCount: number,
  reviewCount: number,
  page: number,
  pages: number,
  totalInScope: number,
): string {
  return `<section class="audit-selector-page">
    <header class="audit-subpage-header">
      <div>
        <span class="eyebrow">TERMINALES GPS + DVR</span>
        <strong>Elegir identidad móvil</strong>
        <small>La selección vive en esta página y no ocupa espacio durante el diagnóstico.</small>
      </div>
      <div class="audit-scope-tabs">
        <button class="${auditTerminalScope === "mobile" ? "active" : ""}" data-audit-scope="mobile">Móviles <b>${mobileCount}</b></button>
        <button class="${auditTerminalScope === "review" ? "active" : ""}" data-audit-scope="review">Revisar <b>${reviewCount}</b></button>
      </div>
    </header>
    <div class="audit-selector-grid">
      ${visibleTerminals.length === 0
        ? `<div class="audit-empty-list"><strong>Sin terminales en esta categoría</strong><span>${auditTerminalScope === "mobile" ? "Ninguna identidad confirmó Android/iOS con runtime Capacitor." : "No hay identidades históricas o incompletas para revisar."}</span></div>`
        : visibleTerminals.map((terminal) => {
            const key = auditTerminalKey(terminal);
            const activity = terminal.heartbeatAt || terminal.fixAt || terminal.lastBatchReceivedAt;
            return `<button class="audit-terminal-choice" data-audit-terminal="${escapeHtml(key)}">
              <span class="audit-terminal-avatar">${terminal.terminalClass === "capacitor_mobile" ? "M" : "?"}</span>
              <span>
                <strong>${escapeHtml(auditTerminalName(terminal))}</strong>
                <small>${escapeHtml(auditTerminalClassLabel(terminal))}</small>
                <code>${escapeHtml(terminal.terminalId)}</code>
              </span>
              <span class="audit-terminal-recency"><i class="${auditTerminalClassTone(terminal)}"></i>${escapeHtml(auditAge(activity))}</span>
              <b>Abrir terminal ›</b>
            </button>`;
          }).join("")}
    </div>
    <footer class="audit-pagination">
      <button id="previous-audit-terminal-page" class="secondary compact" ${page === 0 ? "disabled" : ""}>Anterior</button>
      <span>${totalInScope ? `${page + 1} / ${pages}` : "0 / 0"}</span>
      <button id="next-audit-terminal-page" class="secondary compact" ${page >= pages - 1 || totalInScope === 0 ? "disabled" : ""}>Siguiente</button>
    </footer>
  </section>`;
}

function renderAuditServices(
  gateway: NodeAuditService | undefined,
  broker: NodeAuditService | undefined,
  projector: NodeAuditService | undefined,
  postgres: NodeAuditService | undefined,
  connector: NodeAuditService | undefined,
  snapshot: NodeAuditSnapshot | null,
): string {
  const unresolved = snapshot?.telemetry.unresolvedDeadLetters ?? 0;
  const mainRouteHealthy = [gateway, broker, projector].every(auditServiceHealthy);
  return `<section class="audit-services-page">
    <header class="audit-subpage-header">
      <div>
        <span class="eyebrow">INFRAESTRUCTURA DEL NODO</span>
        <strong>${mainRouteHealthy && snapshot?.databaseOk ? "Ruta de telemetría operativa" : "Servicios que requieren revisión"}</strong>
        <small>Estado unificado del recorrido; los nombres de contenedor quedan disponibles como detalle técnico.</small>
      </div>
      <div class="button-row">
        <button class="secondary compact" data-audit-operation="status">Estado Docker</button>
        <button class="secondary compact" data-audit-operation="logs">Registros</button>
        <button class="secondary compact" data-audit-operation="verify">Verificar</button>
        <button class="secondary compact" data-audit-operation="restart">Reiniciar nodo</button>
      </div>
    </header>
    <div class="audit-service-table">
      ${auditServiceRow("Gateway", gateway?.health || gateway?.state || "sin servicio", auditServiceHealthy(gateway) ? "ok" : "bad", gateway?.containerName || "telemetry_gateway")}
      ${auditServiceRow("Broker", broker?.health || broker?.state || "sin servicio", auditServiceHealthy(broker) ? "ok" : "bad", broker?.containerName || "broker_nats")}
      ${auditServiceRow("Proyector", projector?.health || projector?.state || "sin servicio", auditServiceHealthy(projector) ? "ok" : "bad", projector?.containerName || "telemetry_projector")}
      ${auditServiceRow("PostgreSQL", snapshot?.databaseOk ? "consultable" : postgres?.health || "sin acceso", snapshot?.databaseOk ? "ok" : "bad", snapshot?.databaseError || postgres?.containerName || "datastore_postgres")}
      ${auditServiceRow("Connectivity", connector?.health || connector?.state || "sin servicio", auditServiceHealthy(connector) ? "ok" : "warning", connector?.containerName || "connectivity_connector")}
      ${auditServiceRow("Dead letters", String(unresolved), unresolved === 0 ? "ok" : "bad", unresolved === 0 ? "Sin eventos irresueltos." : "Abra Incidencias en la terminal para revisar los eventos.")}
    </div>
    <footer class="audit-services-footer">
      <span>Use “Actualizar todo” en la barra superior para renovar servicios y evidencia de terminales en un solo corte.</span>
    </footer>
  </section>`;
}

function auditIssues(
  terminal: NodeTelemetryAudit | null,
  services: NodeAuditService[],
  snapshot: NodeAuditSnapshot | null,
): AuditIssue[] {
  const issues: AuditIssue[] = [];
  const criticalServices = [
    ["telemetry_gateway", "Gateway GPS/DVR"],
    ["broker_nats", "Broker NATS"],
    ["telemetry_projector", "Proyector"],
  ] as const;
  for (const [workload, label] of criticalServices) {
    const service = services.find((candidate) => candidate.workload === workload);
    if (auditServiceHealthy(service)) continue;
    issues.push({
      id: `service:${workload}`,
      tone: "bad",
      title: `${label} no está saludable`,
      detail: service
        ? `${service.containerName}: ${service.state}/${service.health}`
        : `No se encontró el workload ${workload}.`,
      resolution: "Revise la salida del servicio, verifique el nodo y reinícielo sólo si la verificación confirma que quedó detenido.",
      actions: ["logs", "verify", "restart"],
    });
  }
  const connector = services.find((candidate) => candidate.workload === "connectivity_connector");
  if (connector && !auditServiceHealthy(connector)) {
    issues.push({
      id: "service:connectivity_connector",
      tone: "warning",
      title: "Connectivity Edge no está saludable",
      detail: `${connector.containerName}: ${connector.state}/${connector.health}`,
      resolution: "La lectura local puede continuar, pero la convergencia remota requiere revisar Registros y ejecutar Verificar.",
      actions: ["logs", "verify"],
    });
  }
  if (snapshot && !snapshot.databaseOk) {
    issues.push({
      id: "database",
      tone: "bad",
      title: "PostgreSQL no es consultable",
      detail: snapshot.databaseError || "El corte no pudo consultar el almacén de telemetría.",
      resolution: "Verifique el nodo y consulte los registros del contenedor antes de reiniciar los servicios.",
      actions: ["logs", "verify", "restart"],
    });
  }
  const unresolved = snapshot?.telemetry.unresolvedDeadLetters ?? 0;
  if (unresolved > 0) {
    const latestDeadLetter = snapshot?.telemetry.recentDeadLetters?.[0];
    issues.push({
      id: "dead-letters",
      tone: "bad",
      title: `${unresolved} dead letter${unresolved === 1 ? "" : "s"} sin resolver`,
      detail: latestDeadLetter
        ? `${latestDeadLetter.category} · ${latestDeadLetter.reason}`
        : "Hay eventos rechazados por contrato, autorización o proyección.",
      resolution: "Abra Registros para localizar la causa y ejecute Verificar. El Manager no marca ni reinyecta eventos automáticamente.",
      actions: ["logs", "verify"],
    });
  }
  if (auditError) {
    issues.push({
      id: "audit-cut",
      tone: "bad",
      title: "El último corte quedó incompleto",
      detail: auditError,
      resolution: "Actualice el corte. Si persiste, consulte Registros y verifique el nodo.",
      actions: ["refresh", "logs", "verify"],
    });
  }
  if (!terminal) return issues;
  if (!terminal.terminalLabel?.trim()) {
    issues.push({
      id: "identity-name",
      tone: "warning",
      title: "La terminal no publicó su nombre",
      detail: `Se usa ${auditTerminalName(terminal)} como etiqueta local.`,
      resolution: "Abra Aegis en el móvil validado para renovar el heartbeat; las versiones actuales publican el nombre de DeviceGuard.",
      actions: ["refresh-terminal", "support"],
    });
  }
  if (terminal.terminalClass === "unknown") {
    issues.push({
      id: "identity-runtime",
      tone: "warning",
      title: "No se pudo confirmar Capacitor móvil",
      detail: "La metadata histórica no informa una plataforma Android/iOS ni un runtime nativo verificable.",
      resolution: "Actualice Aegis en el dispositivo móvil y deje que publique un heartbeat o un punto GPS nuevo.",
      actions: ["refresh-terminal", "support"],
    });
  } else if (terminal.terminalClass === "non_mobile") {
    issues.push({
      id: "identity-incompatible",
      tone: "neutral",
      title: "Terminal fuera del alcance GPS + DVR",
      detail: `Plataforma ${terminal.terminalPlatform || "desconocida"} · tipo ${terminal.terminalDeviceType || terminal.terminalType || "desconocido"}.`,
      resolution: "GPS + DVR sólo se mantiene para aplicaciones móviles nativas con Capacitor. No requiere reparación en este nodo.",
      actions: [],
    });
  }
  const presence = auditPresenceStage(terminal);
  if (terminal.presenceStatus !== "online" && presence.inferredFromTelemetry) {
    const telemetryAt = auditTerminalTelemetryAt(terminal);
    issues.push({
      id: "heartbeat-relay",
      tone: "warning",
      title: "GPS activo sin heartbeat local",
      detail: `El nodo recibió telemetría ${auditAge(telemetryAt)}, pero la presencia se mantiene en Edge y no se replica con los lotes GPS.`,
      resolution: "La conexión GPS está comprobada; no cambie permisos ni reinicie el nodo por esta advertencia. Actualizar el corte renovará la evidencia local.",
      actions: ["refresh-gps", "support"],
    });
  } else if (terminal.presenceStatus !== "online") {
    issues.push({
      id: "heartbeat",
      tone: terminal.presenceStatus === "degraded" ? "warning" : "bad",
      title: terminal.heartbeatAt ? "Heartbeat móvil sin estado online" : "Sin heartbeat móvil",
      detail: terminal.heartbeatAt
        ? `Último heartbeat ${auditAge(terminal.heartbeatAt)} con estado ${terminal.presenceStatus || "desconocido"}.`
        : "No existe presencia registrada para esta identidad.",
      resolution: "Compruebe conectividad y permisos de segundo plano en el móvil; luego verifique el nodo y revise sus registros.",
      actions: ["refresh-terminal", "verify", "logs"],
    });
  }
  if (terminal.lastBatchStatus === "failed") {
    issues.push({
      id: "batch",
      tone: "bad",
      title: "El último lote GPS falló",
      detail: terminal.lastBatchErrorCode || "El lote fue rechazado sin código de error.",
      resolution: "Consulte Registros para identificar el contrato rechazado y ejecute Verificar antes de reintentar desde el móvil.",
      actions: ["refresh-gps", "logs", "verify"],
    });
  }
  if (!terminal.projectedAt || terminal.continuityStatus === "stale" || terminal.continuityStatus === "degraded") {
    issues.push({
      id: "projection",
      tone: terminal.projectedAt ? "warning" : "bad",
      title: !terminal.projectedAt
        ? "No existe posición proyectada"
        : terminal.continuityStatus === "degraded"
          ? "La continuidad GPS está degradada"
          : "La posición proyectada está vencida",
      detail: terminal.projectedAt
        ? `Última proyección ${auditAge(terminal.projectedAt)}.`
        : "No existe terminal_location_current para esta identidad.",
      resolution: "Revise el proyector y el broker mediante Registros; Verificar confirma el estado completo del nodo.",
      actions: ["refresh-gps", "logs", "verify"],
    });
  }
  const dvrPoints = Number(terminal.dvrPoints24h || 0);
  if (dvrPoints === 0) {
    issues.push({
      id: "dvr-empty",
      tone: "warning",
      title: "Sin recorrido DVR en las últimas 24 horas",
      detail: "El almacén append-only no contiene puntos recientes para esta terminal.",
      resolution: "Compruebe permisos de ubicación en segundo plano y la sesión operativa del móvil; luego verifique el nodo.",
      actions: ["refresh-dvr", "verify", "logs"],
    });
  } else if (!terminal.dvrSessionId) {
    issues.push({
      id: "dvr-session",
      tone: "warning",
      title: "Recorrido DVR sin sesión",
      detail: `${dvrPoints} puntos en 24 h no publican dvrSessionId.`,
      resolution: "Actualice Aegis en el móvil y genere una nueva sesión DVR; los puntos existentes permanecen append-only.",
      actions: ["refresh-dvr", "support"],
    });
  }
  return issues;
}

function renderAuditIssueAction(action: string): string {
  if (action === "refresh") return `<button class="secondary compact" data-audit-refresh-scope="all">Actualizar corte</button>`;
  if (action === "refresh-terminal") return `<button class="secondary compact" data-audit-refresh-scope="terminal">Actualizar terminal</button>`;
  if (action === "refresh-gps") return `<button class="secondary compact" data-audit-refresh-scope="gps">Actualizar GPS</button>`;
  if (action === "refresh-dvr") return `<button class="secondary compact" data-audit-refresh-scope="dvr">Actualizar DVR</button>`;
  if (action === "support") return "";
  return `<button class="secondary compact" data-audit-operation="${action}">${escapeHtml(actionLabels[action])}</button>`;
}

function renderAuditSuggestionPanel(issues: AuditIssue[]): string {
  const pageSize = 3;
  const pages = Math.max(1, Math.ceil(issues.length / pageSize));
  auditIssuePage = Math.min(Math.max(0, auditIssuePage), pages - 1);
  const visible = issues.slice(auditIssuePage * pageSize, (auditIssuePage + 1) * pageSize);
  if (issues.length === 0) return "";
  return `<section class="audit-suggestion-panel" aria-label="Análisis y acciones sugeridas">
    <div class="audit-suggestion-list">
      ${visible.map((issue) => `<article class="audit-suggestion-row ${issue.tone}">
        <div>
          <span>${issue.tone === "bad" ? "Crítica" : issue.tone === "warning" ? "Advertencia" : "Informativa"}</span>
          <strong>${escapeHtml(issue.title)}</strong>
          <small>${escapeHtml(issue.detail)} · ${escapeHtml(issue.resolution)}</small>
        </div>
        <div class="audit-suggestion-actions">
          ${issue.actions.map(renderAuditIssueAction).join("")}
        </div>
      </article>`).join("")}
    </div>
    ${pages > 1 ? `<footer class="audit-pagination">
      <button id="previous-audit-issue-page" class="secondary compact" ${auditIssuePage === 0 ? "disabled" : ""}>Anterior</button>
      <span>${auditIssuePage + 1} / ${pages}</span>
      <button id="next-audit-issue-page" class="secondary compact" ${auditIssuePage >= pages - 1 ? "disabled" : ""}>Siguiente</button>
    </footer>` : ""}
  </section>`;
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
  const brokerHealthy = auditServiceHealthy(broker);
  const connectorHealthy = auditServiceHealthy(connector);
  const generatedAt = auditSnapshot
    ? new Date(Number(auditSnapshot.generatedAt) * 1_000).toLocaleTimeString()
    : "pendiente";
  const unresolved = auditSnapshot?.telemetry.unresolvedDeadLetters ?? 0;
  const mobileTerminals = terminals.filter((terminal) => terminal.terminalClass === "capacitor_mobile");
  const reviewTerminals = terminals.filter((terminal) => terminal.terminalClass !== "capacitor_mobile");
  if (auditTerminalScope === "mobile" && mobileTerminals.length === 0 && reviewTerminals.length > 0) {
    auditTerminalScope = "review";
  }
  const scopedTerminals = auditTerminalScope === "mobile" ? mobileTerminals : reviewTerminals;
  const pageSize = 4;
  const terminalPages = Math.max(1, Math.ceil(scopedTerminals.length / pageSize));
  auditTerminalPage = Math.min(Math.max(0, auditTerminalPage), terminalPages - 1);
  let selectedTerminal = scopedTerminals.find((terminal) => auditTerminalKey(terminal) === auditSelectedTerminalId) ?? null;
  if (!selectedTerminal && auditSection !== "terminals") {
    selectedTerminal = scopedTerminals[auditTerminalPage * pageSize] ?? scopedTerminals[0] ?? null;
    auditSelectedTerminalId = selectedTerminal ? auditTerminalKey(selectedTerminal) : null;
  }
  const selectedIndex = selectedTerminal
    ? scopedTerminals.findIndex((terminal) => auditTerminalKey(terminal) === auditTerminalKey(selectedTerminal))
    : -1;
  if (selectedIndex >= 0 && Math.floor(selectedIndex / pageSize) !== auditTerminalPage) {
    auditTerminalPage = Math.floor(selectedIndex / pageSize);
  }
  const visibleTerminals = scopedTerminals.slice(auditTerminalPage * pageSize, (auditTerminalPage + 1) * pageSize);
  const selectedIssues = auditIssues(selectedTerminal, services, auditSnapshot);
  const healthyServices = [
    gatewayHealthy,
    brokerHealthy,
    projectorHealthy,
    Boolean(auditSnapshot?.databaseOk),
    connectorHealthy,
  ].filter(Boolean).length;
  const totalServices = 5;
  const activeAuditJob = activeNodeOperation(node);
  const auditOperationMessage = activeAuditJob
    ? `${actionLabels[activeAuditJob.action] ?? activeAuditJob.action}: ${node.displayName}`
    : auditActionMessage ?? `Operaciones · ${node.displayName}`;
  const terminalDetail = selectedTerminal ? `
    <article class="audit-terminal-detail audit-terminal-page">
      <header class="audit-terminal-head">
        <div class="audit-terminal-summary">
          <div class="audit-terminal-title">
            <h3>${escapeHtml(auditTerminalName(selectedTerminal))}</h3>
            <span class="manager-status ${auditTerminalClassTone(selectedTerminal)}">${escapeHtml(auditTerminalClassLabel(selectedTerminal))}</span>
          </div>
          <div class="audit-terminal-identity">
            <span>UUID</span><code>${escapeHtml(selectedTerminal.terminalId)}</code>
            <span>Plataforma</span><code>${escapeHtml(selectedTerminal.terminalPlatform || "sin dato")}</code>
            <span>Runtime</span><code>${escapeHtml(selectedTerminal.terminalRuntime || "sin dato")}</code>
          </div>
        </div>
        <nav class="audit-tabs" aria-label="Plano de auditoría">
          <button class="${auditTab === "gps" ? "active" : ""}" data-audit-tab="gps">GPS</button>
          <button class="${auditTab === "dvr" ? "active" : ""}" data-audit-tab="dvr">DVR</button>
          <button class="${auditTab === "support" ? "active" : ""}" data-audit-tab="support">Soporte <b>${selectedIssues.length}</b></button>
        </nav>
      </header>
      <section class="audit-detail-body">
        ${auditTab === "gps"
          ? renderAuditPlane(
              "gps",
              "Recepción y proyección",
              `Último punto ${auditAge(selectedTerminal.fixAt)} · lote ${selectedTerminal.lastBatchStatus || "sin estado"}`,
              renderGpsAuditTerminal(selectedTerminal, gatewayHealthy, projectorHealthy),
            )
          : auditTab === "dvr"
            ? renderAuditPlane(
                "dvr",
                "Registro append-only",
                `${selectedTerminal.dvrPoints24h || 0} puntos en 24 h · sesión ${selectedTerminal.dvrSessionId || "ausente"}`,
                renderDvrAuditTerminal(selectedTerminal, gatewayHealthy),
              )
            : auditTab === "support"
              ? renderAuditSupport(selectedTerminal, node)
              : ""}
      </section>
    </article>` : `
    <section class="audit-empty-detail">
      <strong>${terminals.length === 0 ? "El nodo todavía no recibió telemetría" : "Seleccione una terminal"}</strong>
      <span>${terminals.length === 0 ? "Una terminal móvil validada aparecerá al entregar su primer heartbeat o lote GPS." : "Abra la página Terminales para elegir la identidad que desea auditar."}</span>
      <button class="primary compact" data-audit-section="terminals">Elegir terminal</button>
    </section>`;

  app.innerHTML = managerAppShell(
    "audit",
    "",
    "",
    `<main class="manager-shell audit-shell ${auditSection === "terminal" ? "has-docks" : ""}">
      ${auditSection === "terminals"
        ? renderAuditTerminalSelector(
            visibleTerminals,
            mobileTerminals.length,
            reviewTerminals.length,
            auditTerminalPage,
            terminalPages,
            scopedTerminals.length,
          )
        : auditSection === "services"
          ? renderAuditServices(gateway, broker, projector, postgres, connector, auditSnapshot)
          : terminalDetail}
      ${auditSection === "terminal" ? `
        <div class="audit-floating-docks ${selectedTerminal && auditTab === "support" ? "has-suggestions" : "single"}">
          ${selectedTerminal && auditTab === "support" ? renderAuditSuggestionChat(selectedIssues) : ""}
          ${renderOperationChat(auditOperationMessage)}
        </div>` : ""}
    </main>
    <div id="busy-overlay" class="busy-overlay ${auditRefreshInProgress && !auditSnapshot ? "visible" : ""}"><div class="spinner"></div><strong>Auditando recorrido…</strong><small>Consultando el nodo local.</small></div>`,
    node,
    renderAuditSectionNavigation(selectedTerminal, healthyServices, totalServices, unresolved, generatedAt),
  );
  bindAuditEvents();
  bindOperationChatEvents(node.key);
  bindRouteEvents();
}

function htAuditStatus(service: NodeAuditService | undefined): { label: string; tone: string } {
  if (!service) return { label: "No materializado", tone: "bad" };
  if (service.state === "running" && service.health === "healthy") return { label: "Operativo", tone: "ok" };
  if (service.state === "running") return { label: service.health || "En ejecución", tone: "warning" };
  return { label: `${service.state} · ${service.health}`, tone: "bad" };
}

function renderNodeHtAudit(): void {
  const node = htAuditNodeIndex == null ? null : managedNodes[htAuditNodeIndex];
  if (!node) {
    viewMode = "manager";
    renderManager();
    return;
  }
  const snapshot = htAuditSnapshot;
  const configuration = snapshot?.configuration;
  const runtime = snapshot?.runtime;
  const radio = snapshot?.services.find((service) => service.workload === "radio_control");
  const turn = snapshot?.services.find((service) => service.workload === "radio_turn");
  const livekit = snapshot?.services.find((service) => service.workload === "radio_livekit");
  const broker = snapshot?.services.find((service) => service.workload === "broker_nats");
  const radioState = htAuditStatus(radio);
  const turnState = htAuditStatus(turn);
  const livekitState = htAuditStatus(livekit);
  const brokerState = htAuditStatus(broker);
  const activeJob = activeNodeOperation(node);
  const operationMessage = activeJob
    ? `${actionLabels[activeJob.action] ?? activeJob.action}: ${node.displayName}`
    : htAuditMessage ?? `Operaciones HT · ${node.displayName}`;
  const generatedAt = snapshot
    ? new Date(Number(snapshot.generatedAt) * 1_000).toLocaleTimeString()
    : "pendiente";
  const generation = runtime?.generation ?? null;
  const checksum = runtime?.checksum?.trim() || "sin checksum";
  const warningCount = snapshot?.findings.filter((finding) => finding.tone === "warning" || finding.tone === "bad").length ?? 0;

  app.innerHTML = managerAppShell(
    "htAudit",
    "",
    "",
    `<main class="manager-shell ht-audit-shell">
      <header class="ht-audit-toolbar">
        <div>
          <span class="eyebrow">AUDITORÍA HT LOCAL</span>
          <h2>${escapeHtml(node.displayName)}</h2>
          <small>Motores, topología aplicada y frontera con la autoridad de canales.</small>
        </div>
        <div class="ht-audit-actions">
          <span>Corte ${escapeHtml(generatedAt)}</span>
          <button id="refresh-ht-audit" class="secondary compact">Actualizar corte</button>
          <button data-ht-operation="audit_ht" class="primary compact">Generar reporte</button>
          <button data-ht-operation="logs_ht" class="secondary compact">Registros HT</button>
          <button data-ht-operation="verify" class="secondary compact">Verificar nodo</button>
          <button data-route="${nodeRoute(node, "configuration")}" class="secondary compact">Configurar nodo</button>
        </div>
      </header>

      ${htAuditError ? `<div class="callout bad"><strong>No se pudo completar el corte HT</strong><span>${escapeHtml(htAuditError)}</span></div>` : ""}
      ${htAuditMessage ? `<div class="callout ${htAuditMessage.startsWith("No se pudo") ? "bad" : "ok"}"><span>${escapeHtml(htAuditMessage)}</span></div>` : ""}

      <section class="ht-audit-summary" aria-label="Resumen HT">
        <article>
          <span>Topología local</span>
          <strong>${configuration?.endpointHostAligned ? "Host alineado" : "Revisar endpoints"}</strong>
          <small>${escapeHtml(configuration?.radioControlPublicUrl || "Radio Control sin URL pública")}</small>
        </article>
        <article>
          <span>Configuración aplicada</span>
          <strong>${generation == null ? "No verificable" : `Generación ${generation}`}</strong>
          <small title="${escapeHtml(checksum)}">${escapeHtml(checksum.length > 24 ? `${checksum.slice(0, 24)}…` : checksum)}</small>
        </article>
        <article>
          <span>Motores autorizados</span>
          <strong>SAF ${configuration?.safEnabled ? "sí" : "no"} · TURN ${configuration?.turnEnabled ? "sí" : "no"} · LiveKit ${configuration?.livekitEnabled ? "sí" : "no"}</strong>
          <small>TURN ${configuration?.turnUrlCount ?? 0} URL · LiveKit ${configuration?.livekitPublicUrl ? "publicado" : "sin URL"}</small>
        </article>
        <article>
          <span>Frontera de autoridad</span>
          <strong>${warningCount === 0 ? "Sin desvíos locales" : `${warningCount} hallazgo${warningCount === 1 ? "" : "s"}`}</strong>
          <small>Los canales y permisos se resuelven en Actium Center.</small>
        </article>
      </section>

      <section class="ht-audit-body">
        <div class="ht-audit-findings">
          <header>
            <span class="eyebrow">DIAGNÓSTICO ESTRUCTURAL</span>
            <strong>Hallazgos accionables</strong>
          </header>
          ${snapshot?.findings.length
            ? snapshot.findings.map((finding) => `<article class="ht-audit-finding ${escapeHtml(finding.tone)}">
                <div>
                  <span>${escapeHtml(finding.code)}</span>
                  <strong>${escapeHtml(finding.title)}</strong>
                  <small>${escapeHtml(finding.detail)}</small>
                </div>
                <p>${escapeHtml(finding.action)}</p>
              </article>`).join("")
            : `<div class="ht-audit-empty"><strong>Esperando evidencia local</strong><span>Actualice el corte para inspeccionar runtime.json y los contenedores HT.</span></div>`}
        </div>
        <div class="ht-audit-services">
          <header>
            <span class="eyebrow">PLANO LOCAL</span>
            <strong>Servicios observados</strong>
          </header>
          ${[
            ["Radio Control", radio, radioState],
            ["Broker NATS", broker, brokerState],
            ["TURN", turn, turnState],
            ["LiveKit", livekit, livekitState],
          ].map(([label, service, state]) => {
            const typedService = service as NodeAuditService | undefined;
            const typedState = state as { label: string; tone: string };
            return `<article>
              <div><span>${escapeHtml(String(label))}</span><strong>${escapeHtml(typedService?.containerName ?? "Sin contenedor")}</strong></div>
              <b class="${escapeHtml(typedState.tone)}">${escapeHtml(typedState.label)}</b>
            </article>`;
          }).join("")}
          <footer>${escapeHtml(configuration?.authorityBoundary || "El nodo ejecuta motores HT; no es autoridad del catálogo de canales.")}</footer>
        </div>
      </section>

      <div class="ht-audit-operation-dock">
        ${renderOperationChat(operationMessage)}
      </div>
    </main>
    <div id="busy-overlay" class="busy-overlay ${!snapshot && !htAuditError ? "visible" : ""}"><div class="spinner"></div><strong>Auditando HT…</strong><small>Consultando configuración aplicada y workloads locales.</small></div>`,
    node,
  );
  bindHtAuditEvents();
  bindOperationChatEvents(node.key);
  bindRouteEvents();
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

function defaultRadioArchivePath(installDir: string): string {
  const separator = system?.platform === "windows" ? "\\" : "/";
  const normalized = installDir.trim().replace(/[\\/]+$/, "");
  const storageRoot = system?.executionBackend === "supervisor" ? "persistent" : "data";
  return `${normalized}${separator}${storageRoot}${separator}radio-archive`;
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
    : configuredBaseUrl;
  const fallbackOrder = configurationValue("CONNECTIVITY_FALLBACK_ORDER", "direct_data_plane");
  const publishedImages = configurationValue("ACTIUM_INSTALL_MODE") === "published_images"
    || configurationValue("ACTIUM_USE_PUBLISHED_IMAGES") === "true";
  const fallbackNetworkAddress = defaultNetworkAddress();
  const configuredNetworkInterface = configurationValue("ACTIUM_NETWORK_INTERFACE", fallbackNetworkAddress?.interface ?? "");
  const configuredNetworkAddress = configurationValue("ACTIUM_NETWORK_ADDRESS", fallbackNetworkAddress?.address ?? "");
  const configuredNetworkPolicy = (configurationValue("ACTIUM_NETWORK_RECONCILIATION_POLICY", "manual") as NetworkReconciliationPolicy);
  app.innerHTML = managerAppShell(
    "configuration",
    "Configuración del nodo",
    `${node.displayName} · topología local persistente`,
    `<main class="manager-shell configuration-shell">
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
          <label>Política del host<select id="config-network-reconciliation-policy">${networkPolicyOptions(configuredNetworkPolicy)}</select><small>Los nodos existentes permanecen manuales salvo autorización explícita.</small></label>
          <label>Interfaz publicada<select id="config-network-interface">${networkInterfaceOptions(configuredNetworkInterface)}</select></label>
          <label>Dirección publicada<select id="config-network-address">${networkAddressOptions(configuredNetworkInterface, configuredNetworkAddress)}</select></label>
          <label>Plano<select id="config-network-plane"><option value="lan" ${configurationValue("ACTIUM_NETWORK_PLANE", "lan") === "lan" ? "selected" : ""}>LAN</option><option value="vpn" ${configurationValue("ACTIUM_NETWORK_PLANE") === "vpn" ? "selected" : ""}>VPN</option><option value="wan" ${configurationValue("ACTIUM_NETWORK_PLANE") === "wan" ? "selected" : ""}>WAN</option><option value="management" ${configurationValue("ACTIUM_NETWORK_PLANE") === "management" ? "selected" : ""}>Gestión</option></select></label>
          <label>Prioridad de publicación<input id="config-network-priority" type="number" min="0" max="1000" value="${escapeHtml(configurationValue("ACTIUM_NETWORK_PRIORITY", "100"))}" /></label>
          <label>Dirección de escucha<input id="config-bind-address" value="${escapeHtml(networkMode === "local_only" ? "127.0.0.1" : configurationValue("DATA_PLANE_BIND_ADDRESS", "0.0.0.0"))}" /></label>
          <label class="wide">URL accesible del nodo<input id="config-public-base-url" type="url" value="${escapeHtml(effectiveBaseUrl)}" /><small>Base local, LAN o VPN desde la que se derivan los endpoints observados.</small></label>
          <label class="wide">Orígenes CORS<input id="config-cors-origins" value="${escapeHtml(configurationValue("DATA_PLANE_CORS_ORIGINS", "https://localhost"))}" /></label>
          <label data-surface="telemetry">Puerto GPS/DVR<input id="config-telemetry-port" type="number" value="${escapeHtml(configurationValue("TELEMETRY_PORT", system.defaultNetworkPorts.telemetryPort.toString()))}" min="1" max="65535" /></label>
          <label data-surface="radio-control">Puerto HT control<input id="config-radio-control-port" type="number" value="${escapeHtml(configurationValue("RADIO_CONTROL_PORT", system.defaultNetworkPorts.radioControlPort.toString()))}" min="1" max="65535" /></label>
          <label data-surface="radio-saf">Puerto Radio S&amp;F<input id="config-radio-saf-port" type="number" value="${escapeHtml(configurationValue("RADIO_SAF_PORT", system.defaultNetworkPorts.radioSafPort.toString()))}" min="1" max="65535" /></label>
          <label data-surface="site-core">Puerto Site Core<input id="config-site-core-port" type="number" value="${escapeHtml(configurationValue("SITE_CORE_PORT", system.defaultNetworkPorts.siteCorePort.toString()))}" min="1" max="65535" /></label>
          <label data-surface="observability">Puerto Prometheus<input id="config-prometheus-port" type="number" value="${escapeHtml(configurationValue("PROMETHEUS_PORT", system.defaultNetworkPorts.prometheusPort.toString()))}" min="1" max="65535" /></label>
          <label data-surface="observability">Puerto Grafana<input id="config-grafana-port" type="number" value="${escapeHtml(configurationValue("GRAFANA_PORT", system.defaultNetworkPorts.grafanaPort.toString()))}" min="1" max="65535" /></label>
          <label class="wide" data-surface="telemetry">Telemetry Ingress HTTP(S)<input id="config-telemetry-ingress-public-url" type="url" value="${escapeHtml(configurationValue("TELEMETRY_INGRESS_PUBLIC_URL", endpointFromBase(effectiveBaseUrl, configurationValue("TELEMETRY_PORT", system.defaultNetworkPorts.telemetryPort.toString()))))}" /><small>Endpoint exacto publicado a operadores y terminales.</small></label>
          <label class="wide" data-surface="telemetry">Telemetry Read HTTP(S)<input id="config-telemetry-read-public-url" type="url" value="${escapeHtml(configurationValue("TELEMETRY_READ_PUBLIC_URL", endpointFromBase(effectiveBaseUrl, configurationValue("TELEMETRY_PORT", system.defaultNetworkPorts.telemetryPort.toString()))))}" /></label>
          <label class="wide" data-surface="observability">Métricas HTTP(S)<input id="config-metrics-public-url" type="url" value="${escapeHtml(configurationValue("METRICS_PUBLIC_URL", endpointFromBase(effectiveBaseUrl, configurationValue("PROMETHEUS_PORT", system.defaultNetworkPorts.prometheusPort.toString()))))}" /></label>
          <label class="wide" data-surface="radio-control">Radio Control HTTP(S)<input id="config-radio-control-public-url" type="url" value="${escapeHtml(configurationValue("RADIO_CONTROL_PUBLIC_URL", endpointFromBase(effectiveBaseUrl, configurationValue("RADIO_CONTROL_PORT", system.defaultNetworkPorts.radioControlPort.toString()))))}" /></label>
          <label class="wide" data-surface="site-core">Site Core HTTP(S)<input id="config-site-core-public-url" type="url" value="${escapeHtml(configurationValue("SITE_CORE_PUBLIC_URL", endpointFromBase(effectiveBaseUrl, configurationValue("SITE_CORE_PORT", system.defaultNetworkPorts.siteCorePort.toString()))))}" /><small>Bootstrap y autoridad local de Control; la clave raiz llega firmada dentro del .adpe.</small></label>
        </div>
        ${networkMode === "trusted_lan" && configuredBaseUrl !== system.suggestedPublicBaseUrl ? `<div class="callout warning"><strong>Ruta de salida distinta</strong><span>El host propone ${escapeHtml(system.suggestedPublicBaseUrl)} por su ruta a Internet, pero la LAN confiable conserva ${escapeHtml(configuredBaseUrl)} hasta que un operador la cambie explícitamente.</span></div>` : ""}
      </section>

      <section class="configuration-card">
        <div>
          <span class="eyebrow">RADIO HT</span>
          <h3>TURN y LiveKit</h3>
          <p>La superficie sigue a los perfiles instalados. Un Site Core puro no muestra esta sección.</p>
        </div>
        <div class="form-grid">
          <label data-surface="radio-turn">Realm TURN<input id="config-turn-realm" value="${escapeHtml(configurationValue("TURN_REALM"))}" placeholder="turn.aegis.example" /></label>
          <label data-surface="radio-turn">IP pública TURN<input id="config-turn-external-ip" value="${escapeHtml(configurationValue("TURN_EXTERNAL_IP"))}" placeholder="203.0.113.10" /></label>
          <label data-surface="radio-turn">Puerto TURN<input id="config-turn-port" type="number" value="${escapeHtml(configurationValue("TURN_PORT", system.defaultNetworkPorts.turnPort.toString()))}" min="1" max="65535" /></label>
          <label data-surface="radio-turn">Puerto TURN TLS<input id="config-turn-tls-port" type="number" value="${escapeHtml(configurationValue("TURN_TLS_PORT", system.defaultNetworkPorts.turnTlsPort.toString()))}" min="1" max="65535" /></label>
          <label data-surface="radio-turn">Puerto UDP inicial<input id="config-turn-min-port" type="number" value="${escapeHtml(configurationValue("TURN_MIN_PORT", system.defaultNetworkPorts.turnMinPort.toString()))}" min="1" max="65535" /></label>
          <label data-surface="radio-turn">Puerto UDP final<input id="config-turn-max-port" type="number" value="${escapeHtml(configurationValue("TURN_MAX_PORT", system.defaultNetworkPorts.turnMaxPort.toString()))}" min="1" max="65535" /></label>
          <label data-surface="radio-livekit">IP anunciada LiveKit<input id="config-livekit-node-ip" value="${escapeHtml(configurationValue("LIVEKIT_NODE_IP"))}" placeholder="10.0.0.20" /></label>
          <label data-surface="radio-livekit">URL pública LiveKit<input id="config-livekit-public-url" value="${escapeHtml(configurationValue("LIVEKIT_PUBLIC_URL"))}" placeholder="wss://livekit.aegis.example" /></label>
          <label data-surface="radio-livekit">Puerto HTTP LiveKit<input id="config-livekit-http-port" type="number" value="${escapeHtml(configurationValue("LIVEKIT_HTTP_PORT", system.defaultNetworkPorts.livekitHttpPort.toString()))}" min="1" max="65535" /></label>
          <label data-surface="radio-livekit">Puerto RTC TCP LiveKit<input id="config-livekit-rtc-tcp-port" type="number" value="${escapeHtml(configurationValue("LIVEKIT_RTC_TCP_PORT", system.defaultNetworkPorts.livekitRtcTcpPort.toString()))}" min="1" max="65535" /></label>
          <label data-surface="radio-livekit">UDP LiveKit inicial<input id="config-livekit-udp-min-port" type="number" value="${escapeHtml(configurationValue("LIVEKIT_UDP_MIN_PORT", system.defaultNetworkPorts.livekitUdpMinPort.toString()))}" min="1" max="65535" /></label>
          <label data-surface="radio-livekit">UDP LiveKit final<input id="config-livekit-udp-max-port" type="number" value="${escapeHtml(configurationValue("LIVEKIT_UDP_MAX_PORT", system.defaultNetworkPorts.livekitUdpMaxPort.toString()))}" min="1" max="65535" /></label>
          <label class="wide" data-surface="radio-turn">TURN URLs<input id="config-turn-urls" value="${escapeHtml(configurationValue("TURN_URLS", configurationValue("TURN_REALM") ? `turn:${configurationValue("TURN_REALM")}:${configurationValue("TURN_PORT", system.defaultNetworkPorts.turnPort.toString())}?transport=udp, turn:${configurationValue("TURN_REALM")}:${configurationValue("TURN_PORT", system.defaultNetworkPorts.turnPort.toString())}?transport=tcp` : ""))}" placeholder="turn:turn.aegis.example:3478?transport=udp, turns:turn.aegis.example:5349" /><small>Lista separada por comas; coincide con el campo publicado desde Actium Center.</small></label>
          <label class="wide" data-surface="radio-saf">Carpeta de archivo Radio HT<input id="config-radio-archive-host-path" value="${escapeHtml(configurationValue("RADIO_ARCHIVE_HOST_PATH", defaultRadioArchivePath(node.installDir)))}" /><small>${system.executionBackend === "supervisor" ? "Supervisor limita el storage a persistent/ dentro del nodo." : "Ruta local absoluta."} Docker conserva ademÃ¡s la copia interna de MinIO.</small></label>
        </div>
      </section>

      <section class="configuration-card" data-surface="connectivity">
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
    <div id="busy-overlay" class="busy-overlay ${busy ? "visible" : ""}"><div class="spinner"></div><strong>Aplicando configuración…</strong><small>Se restaurará la versión anterior si Docker rechaza los cambios.</small></div>`,
    node,
  );
  bindConfigurationEvents();
  bindRouteEvents();
  refreshCapabilitySurface("config-");
  if (connectivity) synchronizeFallbackOrder("config-");
}

function renderRuntimeUnits(): void {
  const node = runtimeUnitsNodeIndex == null ? null : managedNodes[runtimeUnitsNodeIndex];
  if (!node) {
    navigateToRoute("#/dashboard", true);
    return;
  }
  const inventory = runtimeUnitInventory;
  const units = inventory?.units ?? [];
  app.innerHTML = managerAppShell(
    "runtimeUnits",
    "Runtime units",
    "Lifecycle y health independientes sobre un Fabric compartido del host.",
    `<main class="manager-shell runtime-units-shell">
      <section class="runtime-fabric-card">
        <div>
          <span class="eyebrow">FABRIC HOST-SHARED</span>
          <h2>${escapeHtml(inventory?.fabric.composeProject ?? "Cargando Fabric…")}</h2>
          <small>${inventory ? `fabric_id ${escapeHtml(inventory.fabric.fabricId)} · red ${escapeHtml(inventory.fabric.networkName)}` : "Consultando Actium Node Supervisor 0.5.9"}</small>
        </div>
        <div class="runtime-fabric-facts">
          <span>PostgreSQL <strong>1</strong></span>
          <span>NATS <strong>1</strong></span>
          <span>Host <strong>${escapeHtml(inventory?.fabric.hostId ?? "pendiente de enrolamiento")}</strong></span>
        </div>
      </section>
      <section class="runtime-unit-grid">
        ${units.length === 0 ? `<div class="empty-manager"><strong>Topología no disponible</strong><span>${escapeHtml(managerResult?.output ?? "El Supervisor todavía no devolvió runtime units para este deployment.")}</span></div>` : units.map((unit) => {
          const busyUnit = runtimeUnitBusyId === unit.runtimeUnitId;
          const stateTone = unit.state === "ready" ? "ok" : unit.state === "degraded" || unit.state === "alive" ? "warning" : "neutral";
          const stateLabel: Record<RuntimeUnitHealth["state"], string> = {
            ready: "lista",
            alive: "viva, no lista",
            commissioned: "comisionada",
            degraded: "degradada",
          };
          return `<article class="runtime-unit-card">
            <header>
              <div><span class="eyebrow">${escapeHtml(unit.capability.toUpperCase())}</span><h3>${escapeHtml(unit.composeProject)}</h3></div>
              <span class="manager-status ${stateTone}">${escapeHtml(stateLabel[unit.state])}</span>
            </header>
            <dl class="node-facts">
              <div><dt>Vivos</dt><dd>${unit.aliveServices}/${unit.totalServices}</dd></div>
              <div><dt>Listos</dt><dd>${unit.readyServices}/${unit.totalServices}</dd></div>
              <div class="wide"><dt>runtime_unit_id</dt><dd title="${escapeHtml(unit.runtimeUnitId)}">${escapeHtml(unit.runtimeUnitId)}</dd></div>
            </dl>
            ${unit.failures.length > 0 ? `<pre class="runtime-unit-failures">${escapeHtml(unit.failures.join("\n"))}</pre>` : ""}
            <div class="button-row wrap">
              ${["start", "stop", "restart", "verify"].map((action) => `<button class="${action === "start" ? "primary" : "secondary"} compact runtime-unit-action" data-runtime-unit-id="${escapeHtml(unit.runtimeUnitId)}" data-action="${action}" ${busyUnit || runtimeUnitBusyId ? "disabled" : ""}>${busyUnit ? "Procesando…" : actionLabels[action] ?? action}</button>`).join("")}
            </div>
          </article>`;
        }).join("")}
      </section>
      <section class="result ${managerResult ? managerResult.error ? "error" : "success" : "empty"}">
        <strong>${escapeHtml(managerResult?.message ?? "Aislamiento por runtime unit")}</strong>
        <pre>${escapeHtml(managerResult?.output ?? "Detener o reiniciar una capability no ejecuta down sobre las demás unidades ni sobre el Fabric.")}</pre>
      </section>
    </main>`,
    node,
    `<button id="refresh-runtime-units" class="secondary compact" ${runtimeUnitBusyId ? "disabled" : ""}>Actualizar estado</button>`,
  );
  bindRuntimeUnitEvents();
  bindRouteEvents();
}

function bindRuntimeUnitEvents(): void {
  document.querySelector("#refresh-runtime-units")?.addEventListener("click", () => void refreshRuntimeUnits());
  document.querySelectorAll<HTMLButtonElement>(".runtime-unit-action").forEach((button) => {
    button.addEventListener("click", () => {
      const runtimeUnitId = button.dataset.runtimeUnitId;
      const action = button.dataset.action;
      if (runtimeUnitId && action) void executeRuntimeUnitAction(runtimeUnitId, action);
    });
  });
}

async function refreshRuntimeUnits(): Promise<void> {
  const node = runtimeUnitsNodeIndex == null ? null : managedNodes[runtimeUnitsNodeIndex];
  if (!node) return;
  try {
    runtimeUnitInventory = await invoke<RuntimeUnitInventory>("runtime_unit_inventory", {
      request: { installDir: node.installDir },
    });
    managerResult = null;
  } catch (error) {
    runtimeUnitInventory = null;
    managerResult = { message: "No se pudo cargar la topología", output: String(error), error: true };
  }
  if (viewMode === "runtimeUnits") renderRuntimeUnits();
}

async function executeRuntimeUnitAction(runtimeUnitId: string, action: string): Promise<void> {
  const node = runtimeUnitsNodeIndex == null ? null : managedNodes[runtimeUnitsNodeIndex];
  if (!node || runtimeUnitBusyId) return;
  runtimeUnitBusyId = runtimeUnitId;
  renderRuntimeUnits();
  try {
    const result = await invoke<RuntimeActionResult>("execute_runtime_unit", {
      request: { installDir: node.installDir, runtimeUnitId, action },
    });
    managerResult = { message: result.message, output: result.output, error: false };
  } catch (error) {
    managerResult = { message: `No se pudo ejecutar ${action}`, output: String(error), error: true };
  } finally {
    runtimeUnitBusyId = null;
    await refreshRuntimeUnits();
  }
}

async function openRuntimeUnitsForNode(index: number): Promise<void> {
  const node = managedNodes[index];
  if (!node || !node.operational || node.archived) return;
  runtimeUnitsNodeIndex = index;
  runtimeUnitInventory = null;
  managerResult = null;
  viewMode = "runtimeUnits";
  renderRuntimeUnits();
  await refreshRuntimeUnits();
}

function render(): void {
  if (viewMode === "manager") {
    renderManager();
    return;
  }
  if (viewMode === "operations") {
    renderOperations();
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
  if (viewMode === "htAudit") {
    renderNodeHtAudit();
    return;
  }
  if (viewMode === "runtimeUnits") {
    renderRuntimeUnits();
    return;
  }
  const dependencyReady = system.dockerCli && system.composeV2 && system.dockerDaemon;
  const wizardNetworkMode = hasOperationalInstallation()
    ? configuredNetworkMode()
    : installation.recoverableIncompletePreparation && validNetworkMode(installation.config.DATA_PLANE_NETWORK_MODE)
      ? installation.config.DATA_PLANE_NETWORK_MODE
      : "local_only";
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
        <h1>${escapeHtml(system.productDisplayName)}</h1>
      </div>
      <div class="product-version-stack" aria-label="Versiones del producto">
        <span class="channel-badge ${system.productChannel}">CANAL ${escapeHtml(system.productChannel.toUpperCase())}</span>
        <span>Manager ${escapeHtml(system.nodeManagerVersion)}</span>
        <span>Runtime Data Plane ${escapeHtml(system.dataPlaneReleaseVersion)}</span>
        <span>Payload schema ${system.payloadSchemaVersion}</span>
        <span>Site Runtime ${escapeHtml(system.siteRuntimeSchemaVersion)}</span>
      </div>
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
          <div class="callout success">
            <strong>Raíz autorizada del canal ${escapeHtml(system.productChannel.toUpperCase())}</strong>
            <span>${escapeHtml(system.authorizedNodesRoot)} · el Manager rechazará operaciones fuera de este límite.</span>
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
          <p>Importe el paquete <code>.adpe</code> emitido por Actium Center. El Manager verifica firma Ed25519, issuer, audiencia, despliegue y expiración antes de permitir continuar.</p>
          <div class="form-grid">
            <label class="wide">Directorio del nodo<input id="install-dir" value="${escapeHtml(system.defaultInstallDir)}" /><small>Al reabrir el Manager se detectan los componentes existentes y sólo se agregan perfiles.</small></label>
            <div class="wide inline-actions"><button id="inspect-installation" class="secondary small">Detectar instalación</button><span id="installation-state">${hasOperationalInstallation()
              ? "Instalación administrada y operativa detectada"
              : installation.recoverableIncompletePreparation
                ? `Preparación incompleta (${escapeHtml(installation.status ?? "failed")})`
                : "Destino nuevo"}</span></div>
            <label class="file-field wide">Paquete de enrolamiento Actium<input id="bootstrap-package" type="file" accept=".adpe,application/vnd.actium.data-plane-enrollment,text/plain" /><span id="bootstrap-state">${bootstrapValidation ? `${escapeHtml(bootstrapValidation.deploymentName)} · generación ${bootstrapValidation.generation} · firma válida` : "Seleccione el archivo .adpe descargado desde Actium Center"}</span></label>
          </div>
          ${bootstrapValidation ? `<div class="callout success"><strong>Paquete soberano verificado</strong><span>${escapeHtml(bootstrapValidation.deploymentCode)} · expira ${escapeHtml(new Date(bootstrapValidation.expiresAtUnixSeconds * 1000).toLocaleString("es-AR"))} · compatibilidad mínima ${escapeHtml(bootstrapValidation.installerMinVersion)} · perfiles autorizados: ${escapeHtml(bootstrapValidation.profiles.join(", "))}</span></div>` : `<div class="callout warning"><strong>Enrolamiento pendiente</strong><span>No se habilitarán Componentes ni Red hasta validar un .adpe vigente.</span></div>`}
          ${hasDeploymentConflict() ? `<div class="callout warning">
            <strong>Preparación incompleta de otro despliegue</strong>
            <span>El directorio conserva evidencia de ${escapeHtml(installation.deploymentCode ?? installation.deploymentId ?? "otro despliegue")}, pero no existe un nodo operativo. Para instalar ${escapeHtml(bootstrapValidation?.deploymentCode ?? "el nuevo despliegue")}, archive primero esa preparación incompleta.</span>
            ${installation.lastError ? `<small>Último error: ${escapeHtml(installation.lastError)}</small>` : ""}
            <button id="archive-incomplete-preparation" class="secondary small">Archivar preparación y liberar destino</button>
          </div>` : installation.recoverableIncompletePreparation && bootstrapValidation?.deploymentId === installation.deploymentId ? `<div class="callout warning">
            <strong>Reintento seguro disponible</strong>
            <span>La preparación anterior de este mismo despliegue no llegó a ser operativa. Puede continuar y el Manager reintentará sobre el mismo destino.</span>
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
            <label>Nombre técnico<input id="project-name" value="${escapeHtml(composeProjectName("node-01"))}" /></label>
            <label>Modo de red<select id="network-mode">${networkModeOptions(wizardNetworkMode)}</select><small id="network-mode-help">${escapeHtml(networkModeDescription(wizardNetworkMode))}</small></label>
            <label>Política del host<select id="network-reconciliation-policy">${networkPolicyOptions(system.executionBackend === "supervisor" && wizardNetworkMode === "trusted_lan" && defaultNetworkAddress() ? "reconcile_on_operation" : "manual")}</select><small>El modo automático sólo usa la interfaz y dirección elegidas.</small></label>
            <label>Interfaz publicada<select id="network-interface">${networkInterfaceOptions(defaultNetworkAddress()?.interface ?? "")}</select></label>
            <label>Dirección publicada<select id="network-address">${networkAddressOptions(defaultNetworkAddress()?.interface ?? "", defaultNetworkAddress()?.address ?? "")}</select></label>
            <label>Plano<select id="network-plane"><option value="lan">LAN</option><option value="vpn">VPN</option><option value="wan">WAN</option><option value="management">Gestión</option></select></label>
            <label>Prioridad de publicación<input id="network-priority" type="number" min="0" max="1000" value="100" /></label>
            <label>Dirección de escucha<input id="bind-address" value="${wizardNetworkMode === "local_only" ? "127.0.0.1" : "0.0.0.0"}" /></label>
            <label>URL accesible del nodo<input id="public-base-url" type="url" value="${escapeHtml(wizardBaseUrl)}" /><small>Dirección local, LAN o VPN que usarán las terminales y Aegis Control.</small></label>
            <label class="wide">Orígenes CORS<input id="cors-origins" value="http://localhost:5173,http://tauri.localhost,https://localhost" /></label>
            <label data-surface="telemetry">Puerto GPS/DVR<input id="telemetry-port" type="number" value="${system.defaultNetworkPorts.telemetryPort}" min="1" max="65535" /></label>
            <label data-surface="radio-control">Puerto HT control<input id="radio-control-port" type="number" value="${system.defaultNetworkPorts.radioControlPort}" min="1" max="65535" /></label>
            <label data-surface="radio-saf">Puerto Radio S&amp;F<input id="radio-saf-port" type="number" value="${system.defaultNetworkPorts.radioSafPort}" min="1" max="65535" /></label>
            <label data-surface="site-core">Puerto Site Core<input id="site-core-port" type="number" value="${system.defaultNetworkPorts.siteCorePort}" min="1" max="65535" /></label>
            <label data-surface="observability">Puerto Prometheus<input id="prometheus-port" type="number" value="${system.defaultNetworkPorts.prometheusPort}" min="1" max="65535" /></label>
            <label data-surface="observability">Puerto Grafana<input id="grafana-port" type="number" value="${system.defaultNetworkPorts.grafanaPort}" min="1" max="65535" /></label>
          </div>
          <details data-surface="radio-turn">
            <summary>Configuración avanzada de TURN</summary>
            <div class="form-grid details-grid">
              <label>Realm TURN<input id="turn-realm" placeholder="turn.aegis.example" /></label>
              <label>IP pública TURN<input id="turn-external-ip" placeholder="203.0.113.10" /></label>
              <label>Puerto TURN<input id="turn-port" type="number" value="${system.defaultNetworkPorts.turnPort}" min="1" max="65535" /></label>
              <label>Puerto TURN TLS<input id="turn-tls-port" type="number" value="${system.defaultNetworkPorts.turnTlsPort}" min="1" max="65535" /></label>
              <label>Puerto UDP inicial<input id="turn-min-port" type="number" value="${system.defaultNetworkPorts.turnMinPort}" /></label>
              <label>Puerto UDP final<input id="turn-max-port" type="number" value="${system.defaultNetworkPorts.turnMaxPort}" /></label>
            </div>
          </details>
          <details data-surface="radio-livekit">
            <summary>Configuración avanzada de LiveKit</summary>
            <div class="form-grid details-grid">
              <label>IP anunciada LiveKit<input id="livekit-node-ip" placeholder="10.0.0.20" /></label>
              <label>URL pública LiveKit<input id="livekit-public-url" placeholder="wss://livekit.aegis.example" /></label>
              <label>Puerto HTTP LiveKit<input id="livekit-http-port" type="number" value="${system.defaultNetworkPorts.livekitHttpPort}" min="1" max="65535" /></label>
              <label>Puerto RTC TCP LiveKit<input id="livekit-rtc-tcp-port" type="number" value="${system.defaultNetworkPorts.livekitRtcTcpPort}" min="1" max="65535" /></label>
              <label>UDP LiveKit inicial<input id="livekit-udp-min-port" type="number" value="${system.defaultNetworkPorts.livekitUdpMinPort}" min="1" max="65535" /></label>
              <label>UDP LiveKit final<input id="livekit-udp-max-port" type="number" value="${system.defaultNetworkPorts.livekitUdpMaxPort}" min="1" max="65535" /></label>
            </div>
          </details>
          <details data-surface="connectivity">
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
          <button id="apply-installation" class="primary install-button" ${system.supervisorCompatible === false ? "disabled" : ""}>${hasOperationalInstallation() ? "Aplicar ampliación" : "Instalar y enrolar"}</button>
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
    <div id="busy-overlay" class="busy-overlay ${busy ? "visible" : ""}"><div class="spinner"></div><strong>Procesando…</strong><small>No cierre el Manager.</small></div>
  `;
  bindEvents();
  applyExistingConfig();
  refreshCapabilitySurface();
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
      : composeProjectName(bootstrapValidation?.deploymentCode ?? config.ACTIUM_PROJECT_NAME ?? "node-01"),
  );
  if (validNetworkMode(config.DATA_PLANE_NETWORK_MODE)) {
    setInput("network-mode", config.DATA_PLANE_NETWORK_MODE);
  } else if (hasOperationalInstallation() || installation.recoverableIncompletePreparation) {
    setInput("network-mode", configuredNetworkMode());
  }
  const networkModeHelp = document.querySelector<HTMLElement>("#network-mode-help");
  const networkModeSelect = document.querySelector<HTMLSelectElement>("#network-mode");
  if (networkModeHelp && networkModeSelect && validNetworkMode(networkModeSelect.value)) {
    networkModeHelp.textContent = networkModeDescription(networkModeSelect.value);
  }
  setInput("network-reconciliation-policy", config.ACTIUM_NETWORK_RECONCILIATION_POLICY);
  setInput("network-interface", config.ACTIUM_NETWORK_INTERFACE);
  refreshNetworkAddressOptions("");
  setInput("network-address", config.ACTIUM_NETWORK_ADDRESS);
  setInput("network-plane", config.ACTIUM_NETWORK_PLANE);
  setInput("network-priority", config.ACTIUM_NETWORK_PRIORITY);
  setInput("bind-address", config.DATA_PLANE_BIND_ADDRESS);
  setInput("public-base-url", config.DATA_PLANE_PUBLIC_BASE_URL);
  setInput("cors-origins", config.DATA_PLANE_CORS_ORIGINS);
  setInput("telemetry-port", config.TELEMETRY_PORT);
  setInput("radio-control-port", config.RADIO_CONTROL_PORT);
  setInput("radio-saf-port", config.RADIO_SAF_PORT);
  setInput("site-core-port", config.SITE_CORE_PORT);
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
  const reconciliationPolicy = input("network-reconciliation-policy").value as NetworkReconciliationPolicy;
  if (!["manual", "reconcile_on_operation", "auto_on_interface_change"].includes(reconciliationPolicy)) {
    blockers.push("Seleccione una política de reconciliación válida.");
  } else if (reconciliationPolicy !== "manual" && (!input("network-interface").value || !input("network-address").value)) {
    blockers.push("La reconciliación automatizada exige interfaz y dirección explícitas.");
  }
  const required = ["project-name", "bind-address", "public-base-url", "cors-origins", ...visiblePortFieldIds(selectedProfiles())];
  if (required.some((id) => !input(id).value.trim() || !input(id).checkValidity())) {
    blockers.push(networkConfigurationDeferred
      ? "La configuración local segura no pudo completarse automáticamente."
      : "Complete nombre, bind, URL, CORS y los puertos de los perfiles seleccionados.");
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
  if (selected.has("site-core")) claimPort("TCP", integerValue("site-core-port"), "Site Core");
  if (selected.has("radio-control")) {
    claimPort("TCP", integerValue("radio-control-port"), "HT control");
  }
  if (selected.has("radio-saf")) claimPort("TCP", integerValue("radio-saf-port"), "Radio S&F");
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
    const unauthorized = selectedProfiles().filter((profile) => !((hasOperationalInstallation() || installation.recoverableIncompletePreparation) && installation.profiles.includes(profile)) && !bootstrapValidation?.profiles.includes(profile));
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
  const lockedProfiles = hasOperationalInstallation() || installation.recoverableIncompletePreparation
    ? installation.profiles
    : [];
  return [...new Set([...lockedProfiles, ...checked])];
}

function refreshCapabilitySurface(prefix: "" | "config-" = ""): void {
  const selected = prefix === "config-"
    ? (configurationNodeIndex == null ? [] : managedNodes[configurationNodeIndex]?.profiles ?? [])
    : selectedProfiles();
  const effective = new Set(effectiveProfiles(selected));
  document.querySelectorAll<HTMLElement>("[data-surface]").forEach((element) => {
    const surface = element.dataset.surface ?? "";
    if (surface && surface !== "common") element.hidden = !effective.has(surface);
  });
}

function integerValue(id: string): number {
  return Number.parseInt(input(id).value, 10);
}

function applyNetworkPortPlan(plan: NetworkPortPlan, prefix: "" | "config-" = ""): void {
  const surfaceProfiles = prefix === "config-"
    ? (configurationNodeIndex == null ? [] : managedNodes[configurationNodeIndex]?.profiles ?? [])
    : selectedProfiles();
  const activePortIds = new Set(visiblePortFieldIds(surfaceProfiles));
  const derivedEndpoints = prefix === "config-"
    ? [
        ["config-telemetry-ingress-public-url", "config-telemetry-port"],
        ["config-telemetry-read-public-url", "config-telemetry-port"],
        ["config-metrics-public-url", "config-prometheus-port"],
        ["config-radio-control-public-url", "config-radio-control-port"],
        ["config-site-core-public-url", "config-site-core-port"],
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
    ["radio-saf-port", plan.radioSafPort],
    ["site-core-port", plan.siteCorePort],
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
  for (const [id, value] of values) {
    if (!activePortIds.has(id)) continue;
    input(`${prefix}${id}`).value = String(value);
  }
  if (prefix !== "config-") return;

  const publicBaseUrl = input("config-public-base-url").value;
  for (const derived of derivedEndpoints) {
    if (!derived.followsBase) continue;
    const portId = derived.endpointId.includes("metrics")
      ? "config-prometheus-port"
      : derived.endpointId.includes("radio-control")
      ? "config-radio-control-port"
      : derived.endpointId.includes("site-core")
        ? "config-site-core-port"
      : "config-telemetry-port";
    input(derived.endpointId).value = endpointFromBase(publicBaseUrl, input(portId).value);
  }
  if (previousTurnPort && activePortIds.has("turn-port")) {
    const turnPortPattern = new RegExp(`:${previousTurnPort}(?=[/?]|$)`, "g");
    input("config-turn-urls").value = input("config-turn-urls").value.replace(
      turnPortPattern,
      `:${plan.turnPort}`,
    );
  }
  if (previousLiveKitHttpPort && activePortIds.has("livekit-http-port")) {
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
    const assigned = visiblePortFieldIds(selectedProfiles());
    const parts = [
      assigned.includes("site-core-port") ? `Site Core ${plan.siteCorePort}` : "",
      assigned.includes("telemetry-port") ? `GPS/DVR ${plan.telemetryPort}` : "",
      assigned.includes("radio-control-port") ? `HT ${plan.radioControlPort}` : "",
      assigned.includes("radio-saf-port") ? `S&F ${plan.radioSafPort}` : "",
      assigned.includes("prometheus-port") ? `Prometheus ${plan.prometheusPort}` : "",
      assigned.includes("grafana-port") ? `Grafana ${plan.grafanaPort}` : "",
      assigned.includes("turn-port") ? `TURN ${plan.turnPort}/${plan.turnMinPort}-${plan.turnMaxPort}` : "",
      assigned.includes("livekit-http-port") ? `LiveKit ${plan.livekitHttpPort}/${plan.livekitRtcTcpPort}/${plan.livekitUdpMinPort}-${plan.livekitUdpMaxPort}` : "",
    ].filter(Boolean);
    showStepError(`Puertos libres asignados (${effectiveProfiles(selectedProfiles()).join(", ") || "sin perfiles"}): ${parts.join(", ") || "ninguno"}.`);
  }
}

function applyNetworkModeDefaults(prefix: "" | "config-"): void {
  const mode = input(`${prefix}network-mode`).value as NetworkMode;
  const bindAddress = input(`${prefix}bind-address`);
  const publicBaseUrl = input(`${prefix}public-base-url`);
  const reconciliationPolicy = document.querySelector<HTMLSelectElement>(`#${prefix}network-reconciliation-policy`);
  if (mode !== "trusted_lan" && reconciliationPolicy) reconciliationPolicy.value = "manual";
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
      ["config-site-core-public-url", "config-site-core-port"],
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
    networkReconciliationPolicy: input("network-reconciliation-policy").value,
    networkInterface: input("network-interface").value,
    networkAddress: input("network-address").value,
    networkPlane: input("network-plane").value,
    networkPriority: integerValue("network-priority"),
    bindAddress: input("bind-address").value.trim(),
    publicBaseUrl: input("public-base-url").value.trim(),
    corsOrigins: input("cors-origins").value.trim(),
    telemetryPort: integerValue("telemetry-port"),
    radioControlPort: integerValue("radio-control-port"),
    radioSafPort: integerValue("radio-saf-port"),
    siteCorePort: integerValue("site-core-port"),
    radioArchiveHostPath: configurationValue("RADIO_ARCHIVE_HOST_PATH", defaultRadioArchivePath(input("install-dir").value.trim())),
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
    navigateToRoute("#/dashboard");
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
  const installDir = input("install-dir").value.trim();
  const node = managedNodes.find((candidate) => candidate.installDir.toLowerCase() === installDir.toLowerCase());
  try {
    const job = await invoke<NodeOperationJob>("enqueue_node_operation", {
      request: {
        installDir,
        action,
        nodeKey: node?.key,
        nodeLabel: node?.displayName ?? installation.deploymentCode ?? installation.config.ACTIUM_DATA_PLANE_PROJECT,
      },
    });
    operationJobs = await invoke<NodeOperationJob[]>("list_node_operation_jobs");
    selectedOperationJobId = job.id;
    showResult(
      `${actionLabels[action] ?? action} agregada a la cola`,
      "La operación continuará en segundo plano. Puede volver al Dashboard o abrir Operaciones.",
    );
  } catch (error) {
    showResult(`No se pudo ejecutar ${action}`, String(error), true);
  }
}

async function refreshManagedNodes(message?: string): Promise<void> {
  if (managerRefreshing) return;
  managerRefreshing = true;
  if (viewMode === "manager") render();
  try {
    system = await invoke<SystemInfo>("get_system_info");
    managedNodes = await invoke<ManagedNode[]>("list_managed_nodes");
    if (message) managerResult = { message, output: "Inventario local y estado Docker actualizados.", error: false };
  } catch (error) {
    managerResult = { message: "No se pudo actualizar el inventario", output: String(error), error: true };
  } finally {
    managerRefreshing = false;
    if (viewMode === "manager") render();
  }
}

async function runManagedNodeAction(index: number, action: string): Promise<void> {
  const node = managedNodes[index];
  if (!node) return;
  try {
    const job = await invoke<NodeOperationJob>("enqueue_node_operation", {
      request: {
        installDir: node.installDir,
        action,
        nodeKey: node.key,
        nodeLabel: node.displayName,
      },
    });
    operationJobs = await invoke<NodeOperationJob[]>("list_node_operation_jobs");
    selectedOperationJobId = job.id;
    managerResult = {
      message: `${actionLabels[action] ?? action} encolada para ${node.displayName}`,
      output: "La operación continuará en segundo plano.",
      error: false,
    };
  } catch (error) {
    managerResult = { message: `No se pudo ejecutar ${actionLabels[action] ?? action}`, output: String(error), error: true };
  }
  if (viewMode === "manager") render();
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
  if (!node || (!node.operational && !node.recoverable) || node.archived) return;
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
  auditRefreshTimer = window.setTimeout(() => void refreshNodeAudit("background"), 3_000);
}

async function refreshNodeAudit(scope: AuditRefreshScope = "all"): Promise<void> {
  if (auditRefreshInProgress || viewMode !== "audit" || auditNodeIndex == null) return;
  const node = managedNodes[auditNodeIndex];
  if (!node) return;
  stopAuditPolling();
  auditRefreshInProgress = true;
  auditRefreshScope = scope;
  if (!auditSnapshot || scope !== "background") render();
  try {
    auditSnapshot = await invoke<NodeAuditSnapshot>("audit_node_telemetry", {
      request: { installDir: node.installDir },
    });
    auditError = auditSnapshot.databaseError || null;
    if (scope !== "background") {
      const target = scope === "all"
        ? "Corte completo"
        : scope === "terminal"
          ? "Estado de la terminal"
          : `Estado ${scope.toUpperCase()}`;
      auditActionMessage = `${target} actualizado para ${node.displayName}.`;
    }
  } catch (error) {
    auditError = String(error);
    if (scope !== "background") {
      auditActionMessage = `No se pudo actualizar ${scope === "all" ? "el corte" : scope}: ${String(error)}`;
    }
  } finally {
    auditRefreshInProgress = false;
    auditRefreshScope = null;
    if (viewMode === "audit") {
      if (!operationChatOpen) render();
      scheduleAuditRefresh();
    }
  }
}

async function openAuditForNode(index: number): Promise<void> {
  const node = managedNodes[index];
  if (!node || !node.operational || node.archived || !node.profiles.includes("telemetry")) return;
  if (restoreAuditAfterOperation && auditNodeIndex === index && auditSnapshot) {
    restoreAuditAfterOperation = false;
    viewMode = "audit";
    renderNodeAudit();
    scheduleAuditRefresh();
    return;
  }
  restoreAuditAfterOperation = false;
  stopAuditPolling();
  auditNodeIndex = index;
  auditSnapshot = null;
  auditError = null;
  auditTab = "gps";
  auditSection = "services";
  auditTerminalScope = "mobile";
  auditSelectedTerminalId = null;
  auditTerminalPage = 0;
  auditIssuePage = 0;
  auditEvidencePage = 0;
  auditEvidenceScope = "terminal";
  auditSuggestionsOpen = false;
  auditSupportJobId = null;
  auditDiagnosticJobId = null;
  auditActionMessage = null;
  operationChatOpen = false;
  operationChatSelectedNodeKey = null;
  operationChatSelectedJobId = null;
  operationChatPreferredJobId = null;
  operationChatHistoryPage = 0;
  viewMode = "audit";
  render();
  await refreshNodeAudit("all");
}

async function refreshNodeHtAudit(): Promise<void> {
  const node = htAuditNodeIndex == null ? null : managedNodes[htAuditNodeIndex];
  if (!node || viewMode !== "htAudit") return;
  htAuditError = null;
  if (!htAuditSnapshot) renderNodeHtAudit();
  try {
    htAuditSnapshot = await invoke<NodeHtAuditSnapshot>("audit_node_ht", {
      request: { installDir: node.installDir },
    });
    htAuditMessage = `Corte HT actualizado para ${node.displayName}.`;
  } catch (error) {
    htAuditError = String(error);
    htAuditMessage = null;
  }
  if (viewMode === "htAudit") renderNodeHtAudit();
}

async function openHtAuditForNode(index: number): Promise<void> {
  const node = managedNodes[index];
  if (
    !node
    || !node.operational
    || node.archived
    || !node.profiles.some((profile) => profile.startsWith("radio-"))
  ) return;
  stopAuditPolling();
  htAuditNodeIndex = index;
  htAuditSnapshot = null;
  htAuditError = null;
  htAuditMessage = null;
  operationChatOpen = false;
  operationChatSelectedNodeKey = null;
  operationChatSelectedJobId = null;
  operationChatPreferredJobId = null;
  operationChatHistoryPage = 0;
  viewMode = "htAudit";
  renderNodeHtAudit();
  await refreshNodeHtAudit();
}

async function runHtAuditAction(action: "audit_ht" | "logs_ht" | "verify"): Promise<void> {
  const node = htAuditNodeIndex == null ? null : managedNodes[htAuditNodeIndex];
  if (!node) return;
  try {
    const job = await invoke<NodeOperationJob>("enqueue_node_operation", {
      request: {
        installDir: node.installDir,
        action,
        nodeKey: node.key,
        nodeLabel: node.displayName,
      },
    });
    operationJobs = await invoke<NodeOperationJob[]>("list_node_operation_jobs");
    selectedOperationJobId = job.id;
    operationChatPreferredJobId = job.id;
    htAuditMessage = `${actionLabels[action]} encolada para ${node.displayName}.`;
  } catch (error) {
    htAuditMessage = `No se pudo encolar ${actionLabels[action]}: ${String(error)}`;
  }
  if (viewMode === "htAudit") renderNodeHtAudit();
}

async function runAuditNodeAction(action: "status" | "logs" | "verify" | "restart" | "diagnostics"): Promise<void> {
  const node = auditNodeIndex == null ? null : managedNodes[auditNodeIndex];
  if (!node) return;
  try {
    const job = await invoke<NodeOperationJob>("enqueue_node_operation", {
      request: {
        installDir: node.installDir,
        action,
        nodeKey: node.key,
        nodeLabel: node.displayName,
      },
    });
    operationJobs = await invoke<NodeOperationJob[]>("list_node_operation_jobs");
    selectedOperationJobId = job.id;
    operationChatPreferredJobId = job.id;
    if (action === "logs" || action === "diagnostics") {
      auditSupportJobId = job.id;
      auditEvidenceScope = "services";
      auditEvidencePage = 0;
      auditTab = "support";
      auditSection = "terminal";
    }
    if (action === "diagnostics") {
      auditDiagnosticJobId = job.id;
    }
    auditActionMessage = `${actionLabels[action]} encolada para ${node.displayName}. La auditoría continúa disponible.`;
  } catch (error) {
    auditActionMessage = `No se pudo encolar ${actionLabels[action]}: ${String(error)}`;
  }
  if (viewMode === "audit") renderNodeAudit();
}

async function runAuditRefreshOperation(scope: "terminal" | "gps" | "dvr"): Promise<void> {
  const node = auditNodeIndex == null ? null : managedNodes[auditNodeIndex];
  const terminal = selectedAuditTerminal();
  if (!node || !terminal) {
    auditActionMessage = "Seleccione una terminal antes de actualizar su evidencia.";
    render();
    return;
  }
  const action = scope === "terminal" ? "audit_terminal" : scope === "gps" ? "audit_gps" : "audit_dvr";
  try {
    const job = await invoke<NodeOperationJob>("enqueue_node_operation", {
      request: {
        installDir: node.installDir,
        action,
        nodeKey: node.key,
        nodeLabel: node.displayName,
        terminalId: terminal.terminalId,
      },
    });
    operationJobs = await invoke<NodeOperationJob[]>("list_node_operation_jobs");
    selectedOperationJobId = job.id;
    operationChatPreferredJobId = job.id;
    auditActionMessage = `${actionLabels[action]} encolada para ${auditTerminalName(terminal)}.`;
    if (viewMode === "audit") renderNodeAudit();
    await refreshNodeAudit(scope);
  } catch (error) {
    auditActionMessage = `No se pudo encolar ${actionLabels[action]}: ${String(error)}`;
    if (viewMode === "audit") renderNodeAudit();
  }
}

function selectedAuditTerminal(): NodeTelemetryAudit | null {
  const terminals = auditSnapshot?.telemetry.terminals ?? [];
  return terminals.find((terminal) => auditTerminalKey(terminal) === auditSelectedTerminalId)
    ?? terminals.find((terminal) => terminal.terminalClass === "capacitor_mobile")
    ?? terminals[0]
    ?? null;
}

async function copyDiagnosticReport(report: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(report);
    return;
  }
  const textarea = document.createElement("textarea");
  textarea.value = report;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.select();
  const copied = document.execCommand("copy");
  textarea.remove();
  if (!copied) throw new Error("El portapapeles no está disponible.");
}

async function handleAuditDiagnostic(action: "generate" | "copy" | "export"): Promise<void> {
  const node = auditNodeIndex == null ? null : managedNodes[auditNodeIndex];
  const terminal = selectedAuditTerminal();
  if (!node || !terminal) {
    auditActionMessage = "Seleccione una terminal con evidencia antes de generar el informe.";
    render();
    return;
  }
  if (action === "generate") {
    await refreshNodeAudit("all");
    await runAuditNodeAction("diagnostics");
    return;
  }
  const job = currentAuditDiagnosticJob();
  if (!job || !isTerminalJob(job) || job.state === "cancelled") {
    auditActionMessage = "El informe completo todavía no terminó de reunir evidencia.";
    render();
    return;
  }
  const report = buildAuditDiagnosticReport(node, terminal, auditIssues(terminal, auditSnapshot?.services ?? [], auditSnapshot));
  try {
    if (action === "copy") {
      await copyDiagnosticReport(report);
      auditActionMessage = "Informe diagnóstico redactado copiado al portapapeles.";
    } else {
      const result = await invoke<ExportDiagnosticResult>("export_diagnostic_report", {
        request: { nodeLabel: node.displayName, report },
      });
      auditActionMessage = `Informe exportado: ${result.path}`;
    }
  } catch (error) {
    auditActionMessage = `No se pudo ${action === "copy" ? "copiar" : "exportar"} el informe: ${String(error)}`;
  }
  render();
}

function bindAuditEvents(): void {
  document.querySelector("#back-from-audit")?.addEventListener("click", () => {
    stopAuditPolling();
    auditNodeIndex = null;
    auditSnapshot = null;
    auditError = null;
    auditSelectedTerminalId = null;
    auditEvidencePage = 0;
    auditSupportJobId = null;
    auditDiagnosticJobId = null;
    auditActionMessage = null;
    navigateToRoute("#/dashboard");
  });
  document.querySelector("#refresh-audit")?.addEventListener("click", () => void refreshNodeAudit("all"));
  document.querySelectorAll<HTMLButtonElement>("[data-audit-section]").forEach((button) => {
    button.addEventListener("click", () => {
      const requested = button.dataset.auditSection;
      auditSection = requested === "services"
        ? "services"
        : requested === "terminal" && auditSelectedTerminalId
          ? "terminal"
          : "terminals";
      render();
    });
  });
  document.querySelectorAll<HTMLElement>("[data-audit-refresh-scope]").forEach((button) => {
    button.addEventListener("click", () => {
      const requested = button.dataset.auditRefreshScope;
      const scope: AuditRefreshScope = requested === "terminal"
        ? "terminal"
        : requested === "gps"
          ? "gps"
          : requested === "dvr"
            ? "dvr"
            : "all";
      if (scope === "terminal" || scope === "gps" || scope === "dvr") {
        void runAuditRefreshOperation(scope);
      } else {
        void refreshNodeAudit(scope);
      }
    });
  });
  document.querySelectorAll<HTMLButtonElement>("[data-audit-tab]").forEach((button) => {
    button.addEventListener("click", () => {
      auditTab = button.dataset.auditTab === "dvr"
        ? "dvr"
        : button.dataset.auditTab === "support"
          ? "support"
          : "gps";
      auditIssuePage = 0;
      auditEvidencePage = 0;
      auditSuggestionsOpen = false;
      render();
    });
  });
  document.querySelector<HTMLButtonElement>("[data-audit-suggestions-toggle]")?.addEventListener("click", () => {
    auditSuggestionsOpen = !auditSuggestionsOpen;
    auditIssuePage = 0;
    render();
  });
  document.querySelectorAll<HTMLButtonElement>("[data-audit-open-support]").forEach((button) => {
    button.addEventListener("click", () => {
      const requested = button.dataset.auditOpenSupport;
      auditEvidenceScope = requested === "gps"
        ? "gps"
        : requested === "dvr"
          ? "dvr"
          : "terminal";
      auditEvidencePage = 0;
      auditTab = "support";
      auditSuggestionsOpen = false;
      render();
    });
  });
  document.querySelectorAll<HTMLButtonElement>("[data-audit-evidence-scope]").forEach((button) => {
    button.addEventListener("click", () => {
      const requested = button.dataset.auditEvidenceScope;
      auditEvidenceScope = requested === "gps"
        ? "gps"
        : requested === "dvr"
          ? "dvr"
          : requested === "services"
            ? "services"
            : "terminal";
      auditEvidencePage = 0;
      render();
    });
  });
  document.querySelectorAll<HTMLButtonElement>("[data-audit-scope]").forEach((button) => {
    button.addEventListener("click", () => {
      auditTerminalScope = button.dataset.auditScope === "review" ? "review" : "mobile";
      auditSelectedTerminalId = null;
      auditTerminalPage = 0;
      auditIssuePage = 0;
      auditEvidencePage = 0;
      render();
    });
  });
  document.querySelectorAll<HTMLButtonElement>("[data-audit-terminal]").forEach((button) => {
    button.addEventListener("click", () => {
      auditSelectedTerminalId = button.dataset.auditTerminal ?? null;
      auditSection = "terminal";
      auditIssuePage = 0;
      auditEvidencePage = 0;
      render();
    });
  });
  document.querySelector("#previous-audit-terminal-page")?.addEventListener("click", () => {
    auditTerminalPage = Math.max(0, auditTerminalPage - 1);
    auditSelectedTerminalId = null;
    render();
  });
  document.querySelector("#next-audit-terminal-page")?.addEventListener("click", () => {
    auditTerminalPage += 1;
    auditSelectedTerminalId = null;
    render();
  });
  document.querySelector("#previous-audit-issue-page")?.addEventListener("click", () => {
    auditIssuePage = Math.max(0, auditIssuePage - 1);
    render();
  });
  document.querySelector("#next-audit-issue-page")?.addEventListener("click", () => {
    auditIssuePage += 1;
    render();
  });
  document.querySelector("#previous-audit-evidence-page")?.addEventListener("click", () => {
    auditEvidencePage = Math.max(0, auditEvidencePage - 1);
    render();
  });
  document.querySelector("#next-audit-evidence-page")?.addEventListener("click", () => {
    auditEvidencePage += 1;
    render();
  });
  document.querySelectorAll<HTMLButtonElement>("[data-audit-operation]").forEach((button) => {
    button.addEventListener("click", () => {
      const action = button.dataset.auditOperation;
      if (action === "status" || action === "logs" || action === "verify" || action === "restart") {
        void runAuditNodeAction(action);
      }
    });
  });
  document.querySelectorAll<HTMLButtonElement>("[data-audit-diagnostic]").forEach((button) => {
    button.addEventListener("click", () => {
      const action = button.dataset.auditDiagnostic;
      if (action === "generate" || action === "copy" || action === "export") {
        void handleAuditDiagnostic(action);
      }
    });
  });
}

function bindHtAuditEvents(): void {
  document.querySelector("#refresh-ht-audit")?.addEventListener("click", () => void refreshNodeHtAudit());
  document.querySelectorAll<HTMLButtonElement>("[data-ht-operation]").forEach((button) => {
    button.addEventListener("click", () => {
      const action = button.dataset.htOperation;
      if (action === "audit_ht" || action === "logs_ht" || action === "verify") {
        void runHtAuditAction(action);
      }
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
    networkReconciliationPolicy: input("config-network-reconciliation-policy").value,
    networkInterface: input("config-network-interface").value,
    networkAddress: input("config-network-address").value,
    networkPlane: input("config-network-plane").value,
    networkPriority: integerValue("config-network-priority"),
    bindAddress: input("config-bind-address").value.trim(),
    publicBaseUrl: input("config-public-base-url").value.trim(),
    corsOrigins: input("config-cors-origins").value.trim(),
    telemetryIngressPublicUrl: input("config-telemetry-ingress-public-url").value.trim(),
    telemetryReadPublicUrl: input("config-telemetry-read-public-url").value.trim(),
    metricsPublicUrl: input("config-metrics-public-url").value.trim(),
    radioControlPublicUrl: input("config-radio-control-public-url").value.trim(),
    siteCorePublicUrl: input("config-site-core-public-url").value.trim(),
    turnUrls: input("config-turn-urls").value.trim(),
    telemetryPort: integerValue("config-telemetry-port"),
    radioControlPort: integerValue("config-radio-control-port"),
    radioSafPort: integerValue("config-radio-saf-port"),
    siteCorePort: integerValue("config-site-core-port"),
    radioArchiveHostPath: input("config-radio-archive-host-path").value.trim(),
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

function roamingHost(
  config: Record<string, string>,
  key: string,
  previousBaseUrl: string,
  nextBaseUrl: string,
): string {
  const current = config[key]?.trim() ?? "";
  try {
    const previousHost = new URL(previousBaseUrl).hostname;
    const nextHost = new URL(nextBaseUrl).hostname;
    return !current || current.toLowerCase() === previousHost.toLowerCase() ? nextHost : current;
  } catch {
    return current;
  }
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
    networkReconciliationPolicy: config.ACTIUM_NETWORK_RECONCILIATION_POLICY ?? "manual",
    networkInterface: config.ACTIUM_NETWORK_INTERFACE ?? "",
    networkAddress: config.ACTIUM_NETWORK_ADDRESS ?? "",
    networkPlane: config.ACTIUM_NETWORK_PLANE ?? "lan",
    networkPriority: configuredInteger(config, "ACTIUM_NETWORK_PRIORITY", 100),
    bindAddress: "0.0.0.0",
    publicBaseUrl: nextBaseUrl,
    corsOrigins: config.DATA_PLANE_CORS_ORIGINS ?? "http://localhost:5173,http://tauri.localhost,https://localhost",
    telemetryIngressPublicUrl: roamingEndpoint(config, "TELEMETRY_INGRESS_PUBLIC_URL", "TELEMETRY_PORT", 8090, previousBaseUrl, nextBaseUrl),
    telemetryReadPublicUrl: roamingEndpoint(config, "TELEMETRY_READ_PUBLIC_URL", "TELEMETRY_PORT", 8090, previousBaseUrl, nextBaseUrl),
    metricsPublicUrl: roamingEndpoint(config, "METRICS_PUBLIC_URL", "PROMETHEUS_PORT", 9090, previousBaseUrl, nextBaseUrl),
    radioControlPublicUrl: roamingEndpoint(config, "RADIO_CONTROL_PUBLIC_URL", "RADIO_CONTROL_PORT", 8100, previousBaseUrl, nextBaseUrl),
    siteCorePublicUrl: roamingEndpoint(config, "SITE_CORE_PUBLIC_URL", "SITE_CORE_PORT", 8088, previousBaseUrl, nextBaseUrl),
    turnUrls: config.TURN_URLS ?? "",
    telemetryPort: configuredInteger(config, "TELEMETRY_PORT", 8090),
    radioControlPort: configuredInteger(config, "RADIO_CONTROL_PORT", 8100),
    radioSafPort: configuredInteger(config, "RADIO_SAF_PORT", 8101),
    siteCorePort: configuredInteger(config, "SITE_CORE_PORT", 8088),
    radioArchiveHostPath: config.RADIO_ARCHIVE_HOST_PATH ?? defaultRadioArchivePath(node.installDir),
    prometheusPort: configuredInteger(config, "PROMETHEUS_PORT", 9090),
    grafanaPort: configuredInteger(config, "GRAFANA_PORT", 3001),
    turnRealm: config.TURN_REALM ?? "",
    turnExternalIp: roamingHost(config, "TURN_EXTERNAL_IP", previousBaseUrl, nextBaseUrl),
    turnPort: configuredInteger(config, "TURN_PORT", 3478),
    turnTlsPort: configuredInteger(config, "TURN_TLS_PORT", 5349),
    turnMinPort: configuredInteger(config, "TURN_MIN_PORT", 49160),
    turnMaxPort: configuredInteger(config, "TURN_MAX_PORT", 49200),
    livekitNodeIp: roamingHost(config, "LIVEKIT_NODE_IP", previousBaseUrl, nextBaseUrl),
    livekitPublicUrl: roamingEndpoint(config, "LIVEKIT_PUBLIC_URL", "LIVEKIT_HTTP_PORT", 7880, previousBaseUrl, nextBaseUrl),
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
  if (trustedLanSyncInProgress || busy) return;
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
      if (!applying) {
        applying = true;
        busy = true;
        if (viewMode === "manager") render();
      }
      await invoke<ActionResult>("update_node_configuration", { request });
      trustedLanSyncAttempts.set(node.key, nextBaseUrl);
      synchronized.push(node.displayName);
    }
    if (synchronized.length > 0) {
      managedNodes = await invoke<ManagedNode[]>("list_managed_nodes");
      managerResult = {
        message: "Cambio de LAN aplicado",
        output: `${synchronized.join(", ")} vuelve a publicar sus endpoints derivados desde ${nextBaseUrl}.`,
        error: false,
      };
      if (viewMode === "manager") render();
    }
  } catch (error) {
    managerResult = {
      message: "La nueva LAN requiere revisión",
      output: `La sincronización automática no pudo aplicarse: ${String(error)}. Abra Configurar para revisar la política sin perder la anterior.`,
      error: true,
    };
    if (viewMode === "manager") render();
  } finally {
    if (applying) {
      busy = false;
      if (viewMode === "manager") render();
    }
    trustedLanSyncInProgress = false;
  }
}

// LAN publication is operator-owned. Keep the explicit reconciliation routine
// available, but never invoke it merely because the default Internet route moved.
void synchronizeTrustedLanNodes;

async function saveNodeConfiguration(): Promise<void> {
  const index = configurationNodeIndex;
  if (index == null || !managedNodes[index]) return;
  const node = managedNodes[index];
  const request = nodeConfigurationRequest();
  try {
    const job = await invoke<NodeOperationJob>("enqueue_node_configuration", {
      request: {
        configuration: request,
        nodeKey: node.key,
        nodeLabel: node.displayName,
      },
    });
    operationJobs = await invoke<NodeOperationJob[]>("list_node_operation_jobs");
    selectedOperationJobId = job.id;
    operationChatPreferredJobId = job.id;
    managerResult = {
      message: `Configuración encolada para ${node.displayName}`,
      output: "Se aplicará en segundo plano. El resultado, incluidos los registros de Docker y cualquier conflicto de puertos, quedará disponible en Gestor de Operaciones.",
      error: false,
    };
    configurationNodeIndex = null;
    viewMode = "manager";
    navigateToRoute("#/dashboard");
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

function navigateToRoute(route: string, replace = false): void {
  if (window.location.hash === route) {
    void applyCurrentRoute();
    return;
  }
  if (replace) {
    window.history.replaceState(null, "", route);
    void applyCurrentRoute();
    return;
  }
  window.location.hash = route;
}

function currentReturnRoute(): string {
  const route = window.location.hash || "#/dashboard";
  return route.startsWith("#/operations") ? "#/dashboard" : route;
}

function openOperationDetail(jobId: string): void {
  operationsReturnRoute = currentReturnRoute();
  operationsFocusedJobId = jobId;
  selectedOperationJobId = jobId;
  navigateToRoute(`#/operations/${encodeURIComponent(jobId)}`);
}

function closeOperationDetail(): void {
  const destination = operationsReturnRoute ?? "#/dashboard";
  restoreAuditAfterOperation = destination.includes("/audit");
  operationsFocusedJobId = null;
  operationsReturnRoute = null;
  navigateToRoute(destination);
}

function routeNodeIndex(encodedKey: string): number {
  let key = "";
  try {
    key = decodeURIComponent(encodedKey);
  } catch {
    return -1;
  }
  return managedNodes.findIndex((node) => node.key === key);
}

async function applyCurrentRoute(): Promise<void> {
  const resolution = ++routeResolution;
  const route = window.location.hash || "#/dashboard";
  const segments = route.replace(/^#\/?/, "").split("/").filter(Boolean);
  const area = segments[0] || "dashboard";
  if (area !== "nodes" || segments[2] !== "audit") stopAuditPolling();

  if (area === "dashboard") {
    viewMode = "manager";
    render();
    return;
  }
  if (area === "operations") {
    const encodedJobId = segments[1];
    if (encodedJobId) {
      try {
        operationsFocusedJobId = decodeURIComponent(encodedJobId);
        selectedOperationJobId = operationsFocusedJobId;
      } catch {
        operationsFocusedJobId = null;
      }
    } else {
      operationsFocusedJobId = null;
      operationsReturnRoute = null;
    }
    viewMode = "operations";
    render();
    return;
  }
  if (area !== "nodes") {
    navigateToRoute("#/dashboard", true);
    return;
  }
  if (segments[1] === "new") {
    addNode();
    return;
  }
  const index = routeNodeIndex(segments[1] ?? "");
  if (index < 0) {
    managerResult = { message: "Ruta de nodo no disponible", output: "El nodo ya no pertenece al inventario actual.", error: true };
    navigateToRoute("#/dashboard", true);
    return;
  }
  const destination = segments[2];
  if (destination === "configuration") {
    await openConfigurationForNode(index);
  } else if (destination === "runtime") {
    await openRuntimeUnitsForNode(index);
  } else if (destination === "audit") {
    await openAuditForNode(index);
  } else if (destination === "audit-ht") {
    await openHtAuditForNode(index);
  } else if (destination === "expand") {
    await openWizardForNode(index);
  } else {
    navigateToRoute("#/dashboard", true);
  }
  if (resolution !== routeResolution) return;
}

function bindRouteEvents(): void {
  const sidebarToggle = document.querySelector<HTMLButtonElement>("#toggle-manager-sidebar");
  const managerShell = document.querySelector<HTMLElement>(".manager-app");
  const syncSidebarToggle = (): void => {
    if (!sidebarToggle || !managerShell) return;
    const collapsed = managerShell.classList.contains("sidebar-collapsed");
    sidebarToggle.textContent = collapsed ? "›" : "‹";
    sidebarToggle.setAttribute("aria-label", collapsed ? "Expandir navegación" : "Contraer navegación");
    sidebarToggle.title = collapsed ? "Expandir navegación" : "Contraer navegación";
    sidebarToggle.setAttribute("aria-expanded", String(!collapsed));
  };

  syncSidebarToggle();
  sidebarToggle?.addEventListener("click", () => {
    if (!managerShell) return;
    const collapsed = managerShell.classList.toggle("sidebar-collapsed");
    localStorage.setItem("actium:manager-sidebar-collapsed", String(collapsed));
    syncSidebarToggle();
  });

  document.querySelectorAll<HTMLElement>("[data-route]").forEach((element) => {
    element.addEventListener("click", (event) => {
      event.preventDefault();
      const route = element.dataset.route;
      if (route) {
        if (route === "#/operations") {
          operationsFocusedJobId = null;
          operationsReturnRoute = null;
        }
        navigateToRoute(route);
      }
    });
  });
  document.querySelectorAll<HTMLButtonElement>("[data-operation-job-id]").forEach((button) => {
    button.addEventListener("click", () => {
      const jobId = button.dataset.operationJobId;
      if (jobId) openOperationDetail(jobId);
    });
  });
}

async function copyOperationLog(jobId: string, button: HTMLButtonElement): Promise<void> {
  const job = operationJobs.find((candidate) => candidate.id === jobId);
  if (!job) return;
  const previousLabel = button.textContent ?? "Copiar log";
  button.disabled = true;
  try {
    await copyDiagnosticReport(operationLogText(job));
    button.textContent = "Log copiado";
  } catch (error) {
    button.textContent = "No se pudo copiar";
    managerResult = { message: "No se pudo copiar el registro", output: String(error), error: true };
  } finally {
    window.setTimeout(() => {
      if (!button.isConnected) return;
      button.textContent = previousLabel;
      button.disabled = false;
    }, 1_500);
  }
}

function bindOperationEvents(): void {
  document.querySelectorAll<HTMLButtonElement>("[data-job-id].job-row").forEach((button) => {
    button.addEventListener("click", () => {
      selectedOperationJobId = button.dataset.jobId ?? null;
      renderOperations();
    });
  });
  document.querySelector<HTMLButtonElement>("#copy-operation-log")?.addEventListener("click", (event) => {
    const button = event.currentTarget as HTMLButtonElement;
    const jobId = button.dataset.jobId;
    if (jobId) void copyOperationLog(jobId, button);
  });
  document.querySelector<HTMLButtonElement>("#back-from-operation-detail")?.addEventListener("click", () => {
    closeOperationDetail();
  });
  document.querySelector<HTMLButtonElement>("#cancel-operation")?.addEventListener("click", async (event) => {
    const jobId = (event.currentTarget as HTMLButtonElement).dataset.jobId;
    if (!jobId) return;
    try {
      await invoke<NodeOperationJob>("cancel_node_operation_job", { request: { jobId } });
      operationJobs = await invoke<NodeOperationJob[]>("list_node_operation_jobs");
    } catch (error) {
      managerResult = { message: "No se pudo cancelar la operación", output: String(error), error: true };
    }
    if (viewMode === "operations") renderOperations();
  });
  document.querySelector("#previous-operation-page")?.addEventListener("click", () => {
    operationPage = Math.max(0, operationPage - 1);
    selectedOperationJobId = operationJobs[operationPage * (window.innerHeight >= 900 ? 8 : 6)]?.id ?? null;
    renderOperations();
  });
  document.querySelector("#next-operation-page")?.addEventListener("click", () => {
    operationPage += 1;
    selectedOperationJobId = operationJobs[operationPage * (window.innerHeight >= 900 ? 8 : 6)]?.id ?? null;
    renderOperations();
  });
}

function scheduleOperationPolling(delay: number): void {
  if (operationPollTimer != null) window.clearTimeout(operationPollTimer);
  operationPollTimer = window.setTimeout(() => void refreshOperationJobs(), delay);
}

async function refreshOperationJobs(): Promise<void> {
  try {
    const previousTerminalIds = new Set(operationJobs
      .filter(isTerminalJob)
      .map((job) => job.id));
    const jobs = await invoke<NodeOperationJob[]>("list_node_operation_jobs");
    const snapshot = JSON.stringify(jobs);
    const uiSnapshot = JSON.stringify(jobs.map((job) => ({
      id: job.id,
      nodeKey: job.nodeKey,
      action: job.action,
      state: job.state,
      queuedAtUnixSeconds: job.queuedAtUnixSeconds,
      startedAtUnixSeconds: job.startedAtUnixSeconds,
      finishedAtUnixSeconds: job.finishedAtUnixSeconds,
      message: job.message,
    })));
    const terminalSnapshot = jobs
      .filter(isTerminalJob)
      .map((job) => `${job.id}:${job.state}`)
      .join("|");
    const newlyFinished = jobs.some((job) => (
      isTerminalJob(job) && job.state !== "cancelled" && !previousTerminalIds.has(job.id)
    ));
    operationJobs = jobs;
    if (newlyFinished || terminalSnapshot !== terminalOperationSnapshot) {
      managedNodes = await invoke<ManagedNode[]>("list_managed_nodes").catch(() => managedNodes);
    }
    terminalOperationSnapshot = terminalSnapshot;
    const outputChanged = snapshot !== operationSnapshot;
    const uiChanged = uiSnapshot !== operationUiSnapshot;
    operationSnapshot = snapshot;
    operationUiSnapshot = uiSnapshot;
    if (viewMode === "operations" && outputChanged) {
      renderOperations();
    } else if (viewMode === "manager" && uiChanged) {
      renderManager();
    } else if ((viewMode === "audit" || viewMode === "htAudit") && uiChanged) {
      rerenderOperationChatHost();
    }
  } catch (error) {
    managerResult = { message: "No se pudo leer la cola de operaciones", output: String(error), error: true };
  } finally {
    scheduleOperationPolling(activeOperationJobs().length > 0 ? 800 : 2_500);
  }
}

function rerenderOperationChatHost(): void {
  if (viewMode === "audit" || viewMode === "htAudit") {
    const nodeIndex = viewMode === "audit" ? auditNodeIndex : htAuditNodeIndex;
    const node = nodeIndex == null ? null : managedNodes[nodeIndex];
    const host = document.querySelector<HTMLElement>(".operation-chat");
    if (node && host && operationChatOpen) {
      const activeJob = activeNodeOperation(node);
      const message = activeJob
        ? `${actionLabels[activeJob.action] ?? activeJob.action}: ${node.displayName}`
        : viewMode === "audit"
          ? auditActionMessage ?? `Operaciones · ${node.displayName}`
          : htAuditMessage ?? `Operaciones HT · ${node.displayName}`;
      const wrapper = document.createElement("div");
      wrapper.innerHTML = renderOperationChat(message).trim();
      const replacement = wrapper.firstElementChild;
      if (replacement) {
        host.replaceWith(replacement);
        bindOperationChatEvents(node.key);
      }
    } else {
      if (viewMode === "audit") renderNodeAudit();
      else renderNodeHtAudit();
    }
  } else {
    renderManager();
  }
}

function bindOperationChatEvents(defaultNodeKey?: string): void {
  document.querySelector("#toggle-operation-chat")?.addEventListener("click", () => {
    operationChatOpen = !operationChatOpen;
    const preferredJob = operationChatOpen && operationChatPreferredJobId
      ? operationJobs.find((job) => job.id === operationChatPreferredJobId) ?? null
      : null;
    operationChatSelectedNodeKey = operationChatOpen
      ? preferredJob?.nodeKey ?? defaultNodeKey ?? null
      : null;
    operationChatSelectedJobId = operationChatOpen ? preferredJob?.id ?? null : null;
    operationChatNodePage = 0;
    operationChatHistoryPage = 0;
    rerenderOperationChatHost();
  });
  document.querySelector("#close-operation-chat")?.addEventListener("click", () => {
    operationChatOpen = false;
    operationChatSelectedNodeKey = null;
    operationChatSelectedJobId = null;
    rerenderOperationChatHost();
  });
  document.querySelector("#back-operation-chat")?.addEventListener("click", () => {
    if (operationChatSelectedJobId) {
      operationChatSelectedJobId = null;
    } else {
      operationChatSelectedNodeKey = null;
      operationChatHistoryPage = 0;
    }
    rerenderOperationChatHost();
  });
  document.querySelectorAll<HTMLButtonElement>("[data-chat-node-key]").forEach((button) => {
    button.addEventListener("click", () => {
      operationChatSelectedNodeKey = button.dataset.chatNodeKey ?? null;
      operationChatSelectedJobId = null;
      operationChatHistoryPage = 0;
      rerenderOperationChatHost();
    });
  });
  document.querySelectorAll<HTMLButtonElement>("[data-chat-job-id]").forEach((button) => {
    button.addEventListener("click", () => {
      operationChatSelectedJobId = button.dataset.chatJobId ?? null;
      rerenderOperationChatHost();
    });
  });
  document.querySelector<HTMLButtonElement>("#copy-operation-chat-log")?.addEventListener("click", (event) => {
    const button = event.currentTarget as HTMLButtonElement;
    const jobId = button.dataset.jobId;
    if (jobId) void copyOperationLog(jobId, button);
  });
  document.querySelector<HTMLButtonElement>("#open-operation-chat-log")?.addEventListener("click", (event) => {
    const jobId = (event.currentTarget as HTMLButtonElement).dataset.jobId;
    if (!jobId) return;
    operationChatOpen = false;
    operationChatSelectedJobId = null;
    openOperationDetail(jobId);
  });
  document.querySelector("#previous-operation-chat-node-page")?.addEventListener("click", () => {
    operationChatNodePage = Math.max(0, operationChatNodePage - 1);
    rerenderOperationChatHost();
  });
  document.querySelector("#next-operation-chat-node-page")?.addEventListener("click", () => {
    operationChatNodePage += 1;
    rerenderOperationChatHost();
  });
  document.querySelector("#previous-operation-chat-history-page")?.addEventListener("click", () => {
    operationChatHistoryPage = Math.max(0, operationChatHistoryPage - 1);
    rerenderOperationChatHost();
  });
  document.querySelector("#next-operation-chat-history-page")?.addEventListener("click", () => {
    operationChatHistoryPage += 1;
    rerenderOperationChatHost();
  });
}

function bindManagerEvents(): void {
  document.querySelector("#refresh-nodes")?.addEventListener("click", () => void refreshManagedNodes("Estado actualizado"));
  bindOperationChatEvents();
  document.querySelector("#previous-node-page")?.addEventListener("click", () => {
    managerPage = Math.max(0, managerPage - 1);
    renderManager();
  });
  document.querySelector("#next-node-page")?.addEventListener("click", () => {
    managerPage += 1;
    renderManager();
  });
  document.querySelectorAll<HTMLButtonElement>(".manager-action").forEach((button) => {
    button.addEventListener("click", () => void runManagedNodeAction(Number(button.dataset.nodeIndex), button.dataset.action ?? "status"));
  });
  document.querySelectorAll<HTMLButtonElement>(".promote-node").forEach((button) => {
    button.addEventListener("click", () => void promoteArchivedNode(Number(button.dataset.nodeIndex)));
  });
}

function bindConfigurationEvents(): void {
  document.querySelector("#back-to-manager")?.addEventListener("click", () => {
    configurationNodeIndex = null;
    navigateToRoute("#/dashboard");
  });
  document.querySelector("#cancel-node-configuration")?.addEventListener("click", () => {
    configurationNodeIndex = null;
    navigateToRoute("#/dashboard");
  });
  document.querySelector("#config-network-mode")?.addEventListener("change", () => applyNetworkModeDefaults("config-"));
  document.querySelector("#config-network-interface")?.addEventListener("change", () => refreshNetworkAddressOptions("config-"));
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
  document.querySelector("#network-interface")?.addEventListener("change", () => {
    refreshNetworkAddressOptions("");
    invalidateFrom(3);
  });
  document.querySelector("#defer-network-configuration")?.addEventListener("change", (event) => {
    networkConfigurationDeferred = (event.currentTarget as HTMLInputElement).checked;
    document.querySelector("#wizard-network-fields")?.classList.toggle("deferred", networkConfigurationDeferred);
    if (networkConfigurationDeferred && !hasOperationalInstallation() && !installation.recoverableIncompletePreparation) {
      input("network-mode").value = "local_only";
      applyNetworkModeDefaults("");
    }
    invalidateFrom(3);
  });
  document.querySelector("#connectivity-direct-data-plane-fallback-enabled")?.addEventListener("change", () => synchronizeFallbackOrder(""));
  document.querySelector("#connectivity-supabase-fallback-enabled")?.addEventListener("change", () => synchronizeFallbackOrder(""));
  document.querySelector("#back-to-manager")?.addEventListener("click", () => {
    navigateToRoute("#/dashboard");
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
    refreshCapabilitySurface();
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
    operationJobs = await invoke<NodeOperationJob[]>("list_node_operation_jobs");
    operationSnapshot = JSON.stringify(operationJobs);
    operationUiSnapshot = JSON.stringify(operationJobs.map((job) => ({
      id: job.id,
      nodeKey: job.nodeKey,
      action: job.action,
      state: job.state,
      queuedAtUnixSeconds: job.queuedAtUnixSeconds,
      startedAtUnixSeconds: job.startedAtUnixSeconds,
      finishedAtUnixSeconds: job.finishedAtUnixSeconds,
      message: job.message,
    })));
    terminalOperationSnapshot = operationJobs
      .filter(isTerminalJob)
      .map((job) => `${job.id}:${job.state}`)
      .join("|");
    if (!window.location.hash) {
      navigateToRoute("#/dashboard", true);
    } else {
      await applyCurrentRoute();
    }
    scheduleOperationPolling(activeOperationJobs().length > 0 ? 800 : 2_500);
  } catch (error) {
    app.innerHTML = `<div class="fatal"><h1>No se pudo iniciar Actium Node Manager</h1><pre>${escapeHtml(String(error))}</pre></div>`;
  }
}

window.addEventListener("hashchange", () => void applyCurrentRoute());
let resizeTimer: number | null = null;
window.addEventListener("resize", () => {
  if (resizeTimer != null) window.clearTimeout(resizeTimer);
  resizeTimer = window.setTimeout(() => {
    if (viewMode === "manager") renderManager();
  }, 120);
});

void start();
