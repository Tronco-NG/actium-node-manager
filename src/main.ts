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
};

type InstallationState = {
  installed: boolean;
  managed: boolean;
  version?: string;
  profiles: string[];
  config: Record<string, string>;
  markerPath: string;
};

type ActionResult = {
  ok: boolean;
  message: string;
  output: string;
  installedProfiles: string[];
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
];

let system: SystemInfo;
let installation: InstallationState = {
  installed: false,
  managed: false,
  profiles: [],
  config: {},
  markerPath: "",
};
let bootstrapJws = "";
let bootstrapValidation: BootstrapValidation | null = null;
let activeStep = 0;
let validatedSteps = [false, false, false, false, false];
let busy = false;

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

function profileCards(): string {
  return profiles.map((profile) => {
    const installed = installation.profiles.includes(profile.id);
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

function render(): void {
  const dependencyReady = system.dockerCli && system.composeV2 && system.dockerDaemon;
  app.innerHTML = `
    <header class="topbar">
      <div class="brand-mark">A</div>
      <div>
        <span class="eyebrow">ACTIUM CONTROL PLANE</span>
        <h1>Telemetry Node Installer</h1>
      </div>
      <div class="version-pill">payload ${escapeHtml(system.payloadVersion)}</div>
    </header>
    <main class="shell">
      <aside class="steps">
        <div class="node-summary">
          <span class="eyebrow">ESTE EQUIPO</span>
          <strong>${escapeHtml(system.platform)} / ${escapeHtml(system.architecture)}</strong>
          <small>${installation.installed ? `Nodo ${escapeHtml(installation.version ?? "detectado")}` : "Sin nodo administrado"}</small>
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
            <div class="wide inline-actions"><button id="inspect-installation" class="secondary small">Detectar instalación</button><span id="installation-state">${installation.installed ? "Instalación administrada detectada" : "Destino nuevo"}</span></div>
            <label class="file-field wide">Paquete de enrolamiento Actium<input id="bootstrap-package" type="file" accept=".adpe,application/vnd.actium.data-plane-enrollment,text/plain" /><span id="bootstrap-state">${bootstrapValidation ? `${escapeHtml(bootstrapValidation.deploymentName)} · generación ${bootstrapValidation.generation} · firma válida` : "Seleccione el archivo .adpe descargado desde Actium Center"}</span></label>
          </div>
          ${bootstrapValidation ? `<div class="callout success"><strong>Paquete soberano verificado</strong><span>${escapeHtml(bootstrapValidation.deploymentCode)} · expira ${escapeHtml(new Date(bootstrapValidation.expiresAtUnixSeconds * 1000).toLocaleString("es-AR"))} · perfiles autorizados: ${escapeHtml(bootstrapValidation.profiles.join(", "))}</span></div>` : `<div class="callout warning"><strong>Enrolamiento pendiente</strong><span>No se habilitarán Componentes ni Red hasta validar un .adpe vigente.</span></div>`}
        </div>

        <div class="step-panel ${activeStep === 2 ? "active" : ""}" data-panel="2">
          <span class="eyebrow">PASO 3 · CAPACIDADES</span>
          <div class="title-row"><div><h2>Componentes del nodo</h2><p>Seleccione un nodo completo o sólo los servicios requeridos por esta organización.</p></div><button id="select-all" class="secondary small">Seleccionar todo</button></div>
          <div class="profile-grid">${profileCards()}</div>
          ${installation.installed ? `<div class="callout success"><strong>Ampliación aditiva</strong><span>Los perfiles instalados permanecen bloqueados. El asistente conserva secretos, estado y volúmenes existentes.</span></div>` : ""}
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
          <label class="toggle"><input id="published-images" type="checkbox" /><span></span><div><strong>Usar imágenes publicadas</strong><small>Desactivado: compila imágenes locales reproducibles desde el payload incluido.</small></div></label>
        </div>

        <div class="step-panel ${activeStep === 4 ? "active" : ""}" data-panel="4">
          <span class="eyebrow">PASO 5 · EJECUCIÓN</span>
          <h2>${installation.installed ? "Ampliar o administrar el nodo" : "Instalar el nodo"}</h2>
          <div class="review-card">
            <div><span>Host</span><strong>${escapeHtml(system.platform)} ${escapeHtml(system.architecture)}</strong></div>
            <div><span>Modelo</span><strong>Control Plane Actium + Data Plane local</strong></div>
            <div><span>Modo</span><strong>${installation.installed ? "Ampliación sin pérdida de estado" : "Enrolamiento inicial"}</strong></div>
          </div>
          <label class="toggle"><input id="prepare-only" type="checkbox" /><span></span><div><strong>Sólo preparar</strong><small>Genera configuración y secretos pero no inicia los contenedores.</small></div></label>
          <button id="apply-installation" class="primary install-button">${installation.installed ? "Aplicar ampliación" : "Instalar y enrolar"}</button>
          <div class="operations ${installation.installed ? "visible" : ""}">
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
  setInput("project-name", config.ACTIUM_PROJECT_NAME);
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
  if (step === 1) return Boolean(input("install-dir").value.trim() && bootstrapJws && bootstrapValidation?.valid);
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
  } else if (step === 2) {
    const unauthorized = selectedProfiles().filter((profile) => !installation.profiles.includes(profile) && !bootstrapValidation?.profiles.includes(profile));
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
  return [...new Set([...installation.profiles, ...checked])];
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
    usePublishedImages: input("published-images").checked,
    prepareOnly: input("prepare-only").checked,
  };
}

async function applyInstallation(): Promise<void> {
  setBusy(true);
  try {
    const result = await invoke<ActionResult>("apply_installation", { request: installRequest() });
    installation.profiles = result.installedProfiles;
    installation.installed = true;
    installation.managed = true;
    showResult(result.message, result.output);
    document.querySelector(".operations")?.classList.add("visible");
  } catch (error) {
    showResult("La instalación no pudo completarse", String(error), true);
  } finally {
    setBusy(false);
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

function bindEvents(): void {
  document.querySelectorAll<HTMLButtonElement>("[data-step]").forEach((button) => {
    button.addEventListener("click", () => {
      const target = Number(button.dataset.step);
      changeStep(target);
    });
  });
  document.querySelector("#previous")?.addEventListener("click", () => changeStep(activeStep - 1));
  document.querySelector("#next")?.addEventListener("click", () => void advanceTo(activeStep + 1));
  document.querySelector("#refresh-system")?.addEventListener("click", refreshSystem);
  document.querySelector("#inspect-installation")?.addEventListener("click", inspectInstallation);
  document.querySelector("#bootstrap-package")?.addEventListener("change", (event) => void loadBootstrap(event.currentTarget as HTMLInputElement));
  document.querySelector("#install-dir")?.addEventListener("input", () => invalidateFrom(1));
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
    installation = await invoke<InstallationState>("inspect_installation", {
      request: { installDir: system.defaultInstallDir },
    });
    render();
  } catch (error) {
    app.innerHTML = `<div class="fatal"><h1>No se pudo iniciar el instalador</h1><pre>${escapeHtml(String(error))}</pre></div>`;
  }
}

void start();
