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
  unhealthyServices: number;
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
let viewMode: "manager" | "wizard" = "wizard";
let managedNodes: ManagedNode[] = [];
let wizardTargetPinned = false;
let managerResult: { message: string; output: string; error: boolean } | null = null;

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
                <code class="node-path">${escapeHtml(node.installDir)}</code>
                ${node.lastError ? `<div class="node-error">Último error: ${escapeHtml(node.lastError)}</div>` : ""}
                <div class="node-actions">
                  ${node.canManage ? ["status", "verify", "start", "stop", "restart", "update", "logs"]
                    .map((action) => `<button class="secondary small manager-action" data-node-index="${index}" data-action="${action}">${actionLabels[action]}</button>`)
                    .join("") : ""}
                  <button class="secondary small open-wizard" data-node-index="${index}">${node.operational && !node.archived ? "Ampliar con .adpe" : "Recuperar con .adpe"}</button>
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

function render(): void {
  if (viewMode === "manager") {
    renderManager();
    return;
  }
  const dependencyReady = system.dockerCli && system.composeV2 && system.dockerDaemon;
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
        ${["Sistema", "Autoridad Actium", "Componentes", "Red", "Instalar y operar"].map((title, index) => `
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
          ${bootstrapValidation ? `<div class="callout success"><strong>Paquete soberano verificado</strong><span>${escapeHtml(bootstrapValidation.deploymentCode)} · expira ${escapeHtml(new Date(bootstrapValidation.expiresAtUnixSeconds * 1000).toLocaleString("es-AR"))} · perfiles autorizados: ${escapeHtml(bootstrapValidation.profiles.join(", "))}</span></div>` : `<div class="callout warning"><strong>Enrolamiento pendiente</strong><span>No se habilitarán Componentes ni Red hasta validar un .adpe vigente.</span></div>`}
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
          <p>Los valores seguros funcionan en LAN/VPN. Exponga servicios públicos sólo detrás de firewall, TLS y DNS administrado.</p>
          <div class="form-grid">
            <label>Nombre técnico<input id="project-name" value="actium-data-plane-node-01" /></label>
            <label>Dirección de escucha<input id="bind-address" value="0.0.0.0" /></label>
            <label>URL accesible del nodo<input id="public-base-url" type="url" value="${escapeHtml(system.suggestedPublicBaseUrl)}" /><small>Dirección LAN/VPN que usarán las terminales y Aegis Control.</small></label>
            <label class="wide">Orígenes CORS<input id="cors-origins" value="https://localhost" /></label>
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
              <label>Puerto UDP inicial<input id="turn-min-port" type="number" value="49160" /></label>
              <label>Puerto UDP final<input id="turn-max-port" type="number" value="49200" /></label>
              <label>IP anunciada LiveKit<input id="livekit-node-ip" placeholder="10.0.0.20" /></label>
              <label>URL pública LiveKit<input id="livekit-public-url" placeholder="wss://livekit.aegis.example" /></label>
            </div>
          </details>
          <details>
            <summary>Connectivity Edge y recuperación multi-nodo</summary>
            <div class="form-grid details-grid">
              <label class="wide">Control de Connectivity Edge<input id="connectivity-edge-control-url" type="url" placeholder="https://connectivity.example.com" /><small>Plano independiente. No debe apuntar a los cores Supabase de Actium o Aegis.</small></label>
              <label>Token de enrolamiento Edge<input id="connectivity-edge-enrollment-token" type="password" autocomplete="off" placeholder="acen_..." /></label>
              <label>Token de relay interno<input id="connectivity-internal-relay-token" type="password" autocomplete="off" placeholder="acer_..." /></label>
              <label>Rol inicial<select id="connectivity-node-role"><option value="replica">Réplica recuperable</option><option value="primary">Primario</option></select></label>
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
  setInput("project-name", config.ACTIUM_PROJECT_NAME ?? bootstrapValidation?.deploymentCode);
  setInput("bind-address", config.DATA_PLANE_BIND_ADDRESS);
  setInput("public-base-url", config.DATA_PLANE_PUBLIC_BASE_URL);
  setInput("cors-origins", config.DATA_PLANE_CORS_ORIGINS);
  setInput("telemetry-port", config.TELEMETRY_PORT);
  setInput("radio-control-port", config.RADIO_CONTROL_PORT);
  setInput("prometheus-port", config.PROMETHEUS_PORT);
  setInput("grafana-port", config.GRAFANA_PORT);
  setInput("turn-realm", config.TURN_REALM);
  setInput("turn-external-ip", config.TURN_EXTERNAL_IP);
  setInput("turn-min-port", config.TURN_MIN_PORT);
  setInput("turn-max-port", config.TURN_MAX_PORT);
  setInput("livekit-node-ip", config.LIVEKIT_NODE_IP);
  setInput("livekit-public-url", config.LIVEKIT_PUBLIC_URL);
  setInput("connectivity-edge-control-url", config.CONNECTIVITY_EDGE_CONTROL_URL);
  setInput("connectivity-node-role", config.CONNECTIVITY_NODE_ROLE);
  const published = document.querySelector<HTMLInputElement>("#published-images");
  if (published) published.checked = config.ACTIUM_USE_PUBLISHED_IMAGES === "true" || config.ACTIUM_INSTALL_MODE === "published_images";
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
  if (step === 3) {
    const required = ["project-name", "bind-address", "public-base-url", "cors-origins", "telemetry-port", "radio-control-port", "prometheus-port", "grafana-port"];
    if (required.some((id) => !input(id).value.trim() || !input(id).checkValidity())) return false;
    if (!/^[a-z0-9][a-z0-9._-]{2,79}$/.test(input("project-name").value.trim())) return false;
    try {
      const publicUrl = new URL(input("public-base-url").value.trim());
      if (!['http:', 'https:'].includes(publicUrl.protocol)) return false;
    } catch {
      return false;
    }
    const ports = ["telemetry-port", "radio-control-port", "prometheus-port", "grafana-port"].map(integerValue);
    if (new Set(ports).size !== ports.length) return false;
    const selected = new Set(selectedProfiles());
    if (selected.has("radio-turn")) {
      if (!input("turn-realm").value.trim()) return false;
      if (integerValue("turn-min-port") > integerValue("turn-max-port")) return false;
    }
    if (selected.has("radio-livekit") && (!input("livekit-node-ip").value.trim() || !input("livekit-public-url").value.trim().startsWith("wss://"))) return false;
    if (selected.has("connectivity") && !installation.profiles.includes("connectivity") && (
      !input("connectivity-edge-control-url").value.trim().startsWith("https://")
      || !input("connectivity-edge-enrollment-token").value.trim().startsWith("acen_")
      || !input("connectivity-internal-relay-token").value.trim().startsWith("acer_")
    )) return false;
  }
  return true;
}

async function validateStep(step: number): Promise<void> {
  showStepError("");
  if (!isStepLocallyComplete(step)) throw new Error("Complete todos los campos obligatorios de este paso.");
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

function installRequest(): Record<string, unknown> {
  return {
    installDir: input("install-dir").value.trim(),
    bootstrapJws,
    profiles: selectedProfiles(),
    projectName: input("project-name").value.trim(),
    bindAddress: input("bind-address").value.trim(),
    publicBaseUrl: input("public-base-url").value.trim(),
    corsOrigins: input("cors-origins").value.trim(),
    telemetryPort: integerValue("telemetry-port"),
    radioControlPort: integerValue("radio-control-port"),
    prometheusPort: integerValue("prometheus-port"),
    grafanaPort: integerValue("grafana-port"),
    turnRealm: input("turn-realm").value.trim(),
    turnExternalIp: input("turn-external-ip").value.trim(),
    turnMinPort: integerValue("turn-min-port"),
    turnMaxPort: integerValue("turn-max-port"),
    livekitNodeIp: input("livekit-node-ip").value.trim(),
    livekitPublicUrl: input("livekit-public-url").value.trim(),
    connectivityEdgeControlUrl: input("connectivity-edge-control-url").value.trim(),
    connectivityEdgeEnrollmentToken: input("connectivity-edge-enrollment-token").value.trim(),
    connectivityInternalRelayToken: input("connectivity-internal-relay-token").value.trim(),
    connectivityNodeRole: input("connectivity-node-role").value,
    usePublishedImages: input("published-images").checked,
    prepareOnly: input("prepare-only").checked,
  };
}

async function applyInstallation(): Promise<void> {
  setBusy(true);
  try {
    const result = await invoke<ActionResult>("apply_installation", { request: installRequest() });
    installation = await invoke<InstallationState>("inspect_installation", {
      request: { installDir: input("install-dir").value.trim() },
    });
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
  wizardTargetPinned = false;
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
  document.querySelectorAll<HTMLInputElement>('input[name="profiles"]').forEach((checkbox) => checkbox.addEventListener("change", () => invalidateFrom(2)));
  document.querySelectorAll<HTMLInputElement>('[data-panel="3"] input').forEach((field) => {
    field.addEventListener("input", () => invalidateFrom(3));
    field.addEventListener("change", () => invalidateFrom(3));
  });
  document.querySelector("#select-all")?.addEventListener("click", () => {
    document.querySelectorAll<HTMLInputElement>('input[name="profiles"]:not(:disabled)').forEach((checkbox) => { checkbox.checked = true; });
    invalidateFrom(2);
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
  } catch (error) {
    app.innerHTML = `<div class="fatal"><h1>No se pudo iniciar el instalador</h1><pre>${escapeHtml(String(error))}</pre></div>`;
  }
}

void start();
