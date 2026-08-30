#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";

const rootDir = path.resolve(import.meta.dirname, "..");
const tauriDir = path.join(rootDir, "src-tauri");

process.env.ACTIUM_ALLOW_DIRTY = process.env.ACTIUM_ALLOW_DIRTY || "1";

const homeDir = process.env.HOME || (process.platform === "win32" ? process.env.USERPROFILE : "/root");
if (homeDir) {
  const cargoBin = path.join(homeDir, ".cargo", "bin");
  if (fs.existsSync(cargoBin) && !(process.env.PATH || "").includes(cargoBin)) {
    process.env.PATH = `${cargoBin}:${process.env.PATH || ""}`;
  }
}

function runCommand(command, args, options = {}) {
  console.log(`\n\x1b[36m▶ Ejecutando: ${command} ${args.join(" ")}\x1b[0m`);
  const result = spawnSync(command, args, {
    cwd: options.cwd || rootDir,
    stdio: "inherit",
    shell: options.shell ?? (process.platform === "win32"),
    env: { ...process.env, ...(options.env || {}) },
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`El comando falló con código de salida: ${result.status}`);
  }
}

async function askQuestion(rl, query, options, defaultIndex = 0) {
  console.log(`\n\x1b[33m${query}\x1b[0m`);
  options.forEach((opt, index) => {
    console.log(`  [${index + 1}] ${opt.label}`);
  });
  const answer = await rl.question(`Seleccione opción [1-${options.length}] (default: ${defaultIndex + 1}): `);
  const selectedIndex = parseInt(answer.trim(), 10) - 1;
  if (isNaN(selectedIndex) || selectedIndex < 0 || selectedIndex >= options.length) {
    return options[defaultIndex].value;
  }
  return options[selectedIndex].value;
}

function parseArgs(argv) {
  const parsed = { os: null, terminal: null, keepPayload: true, payloadArchive: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--os") parsed.os = argv[++i];
    if (argv[i] === "--terminal") parsed.terminal = true;
    if (argv[i] === "--no-terminal") parsed.terminal = false;
    if (argv[i] === "--keep-payload") parsed.keepPayload = true;
    if (argv[i] === "--refresh-payload") parsed.keepPayload = false;
    if (argv[i] === "--payload-archive") parsed.payloadArchive = argv[++i];
    if (argv[i] === "--channel" || argv[i] === "--target") i += 1;
  }
  return parsed;
}

function restorePayloadArchive(archivePath) {
  const dest = path.join(tauriDir, "resources", "node");
  if (!fs.existsSync(archivePath)) {
    throw new Error(`No se encontró el archivo de payload pinned: ${archivePath}`);
  }
  console.log(`\nRestaurando payload pinned desde ${archivePath}`);
  fs.rmSync(dest, { recursive: true, force: true });
  fs.mkdirSync(dest, { recursive: true });
  const relativeArchive = path.relative(rootDir, archivePath) || archivePath;
  const relativeDest = path.relative(rootDir, dest);
  runCommand("tar", ["--force-local", "-xzf", relativeArchive, "-C", relativeDest], { shell: false });
}

function stageSupervisorResources() {
  const supervisorResDir = path.join(tauriDir, "resources", "supervisor");
  fs.mkdirSync(supervisorResDir, { recursive: true });
  const supervisorSrcDir = path.join(tauriDir, "supervisor");
  if (fs.existsSync(supervisorSrcDir)) {
    fs.cpSync(supervisorSrcDir, supervisorResDir, { recursive: true });
  }
  for (const name of ["actium-node-supervisor.exe", "actium-node-supervisor"]) {
    const src = path.join(tauriDir, "target", "release", name);
    if (fs.existsSync(src)) {
      const dest = path.join(supervisorResDir, name);
      fs.copyFileSync(src, dest);
      if (!name.endsWith(".exe")) fs.chmodSync(dest, 0o755);
    }
  }
  for (const name of ["install-supervisor-debian.sh", "postinst-debian.sh"]) {
    const script = path.join(supervisorResDir, name);
    if (fs.existsSync(script)) fs.chmodSync(script, 0o755);
  }
}

function runPredeployValidations() {
  if (process.env.ACTIUM_SKIP_PREDEPLOY === "1") {
    console.warn("\n\x1b[33mACTIUM_SKIP_PREDEPLOY=1: se omite el contrato pre-despliegue.\x1b[0m");
    return;
  }
  console.log("\n\x1b[34mValidaciones pre-despliegue (release, Center, ceremonia)...\x1b[0m");
  runCommand("node", ["--test", "scripts/predeploy-release-contract.test.mjs"]);
  const centerRoot = process.env.ACTIUM_CENTER_ROOT
    ? path.resolve(process.env.ACTIUM_CENTER_ROOT)
    : path.resolve(rootDir, "../../../../actium-center-control-local-backend");
  const centerContract = path.join(centerRoot, "scripts/predeploy-release-contract.mjs");
  if (!fs.existsSync(centerContract)) {
    throw new Error(`No se encontró ${centerContract}. No se puede validar el pin de Center antes de compilar.`);
  }
  runCommand("node", [centerContract], { cwd: centerRoot });
}

function printCenterReleasePin() {
  const payloadPath = path.join(tauriDir, "resources", "node", "PAYLOAD.json");
  if (!fs.existsSync(payloadPath)) return;
  try {
    const payload = JSON.parse(fs.readFileSync(payloadPath, "utf8"));
    const release = payload.releaseVersion || "(sin versión)";
    const digest = payload.treeSha256 || "(sin digest)";
    console.log("\n\x1b[33mPin para Actium Center\x1b[0m");
    console.log("  Fijar desired release con estos valores. Si el nodo ya corre esta payload:");
    console.log("  no republicar y no pulsar Actualizar en Node Manager.");
    console.log("  El próximo heartbeat sincroniza observed vs desired. Verificar fuerza un reporte.");
    console.log(`  runtime_release: \x1b[36m${release}\x1b[0m`);
    console.log(`  payload_digest:  \x1b[36m${digest}\x1b[0m`);
  } catch (error) {
    console.warn(`No se pudo leer PAYLOAD.json para el pin de Center: ${error.message}`);
  }
}

function copyDebWithoutSpaces() {
  const debDir = path.join(tauriDir, "target", "release", "bundle", "deb");
  if (!fs.existsSync(debDir)) return;
  for (const name of fs.readdirSync(debDir)) {
    if (!name.endsWith(".deb") || !name.includes(" ")) continue;
    const dest = path.join(debDir, name.replaceAll(" ", "-").toLowerCase());
    fs.copyFileSync(path.join(debDir, name), dest);
  }
}

async function main() {
  console.log("\x1b[32m===============================================================");
  console.log("   ACTIUM COMPILADOR MAESTRO");
  console.log("   Node Manager + Supervisor (stable + lab)");
  console.log("===============================================================\x1b[0m");

  const parsed = parseArgs(process.argv.slice(2));
  let targetOS = parsed.os;
  let includeTerminal = parsed.terminal;
  let keepPayload = parsed.keepPayload;

  if (!targetOS || includeTerminal === null) {
    const rl = readline.createInterface({ input, output });
    try {
      if (!targetOS) {
        targetOS = await askQuestion(rl, "1. ¿Para qué Sistema Operativo deseas compilar?", [
          { label: `Windows (${process.platform === "win32" ? "Host actual" : "x86_64"})`, value: "windows" },
          { label: "Linux (Debian / Ubuntu / .deb + Supervisor systemd)", value: "linux" },
          { label: "Ambos (Windows + Linux)", value: "all" },
        ], process.platform === "win32" ? 0 : 1);
      }
      if (includeTerminal === null) {
        includeTerminal = await askQuestion(rl, "2. ¿Generar también instaladores de terminal (zip / tar.gz)?", [
          { label: "Sí (GUI + Supervisor de servicio + paquete para instalar por terminal)", value: true },
          { label: "No (solo instalador GUI, que también actualiza el Supervisor)", value: false },
        ], 0);
      }
      if (!process.argv.includes("--keep-payload") && !process.argv.includes("--refresh-payload")) {
        keepPayload = await askQuestion(rl, "3. ¿Qué hacer con la payload de nodos?", [
          { label: "Conservar payload pinned (cambia UI/Supervisor, NO un release nuevo)", value: true },
          { label: "Regenerar payload desde el workspace (nuevo digest; requiere preset en Center)", value: false },
        ], 0);
      }
    } finally {
      rl.close();
    }
  }

  console.log("\n\x1b[32mConfiguración:\x1b[0m");
  console.log(`  • Sistema Operativo: \x1b[35m${String(targetOS).toUpperCase()}\x1b[0m`);
  console.log("  • Producto:          \x1b[35mNODE MANAGER + SUPERVISOR\x1b[0m");
  console.log(`  • Payload:           \x1b[35m${keepPayload ? "conservar digest pinned" : "regenerar desde workspace"}\x1b[0m`);
  console.log("  • Canales:           \x1b[35mstable + lab por lugar de despliegue, no por otra release\x1b[0m");
  console.log(`  • Terminal:          \x1b[35m${includeTerminal ? "SÍ" : "NO"}\x1b[0m`);

  console.log("\n\x1b[34m[Paso 1/3] Preparando y validando el payload de contratos...\x1b[0m");
  if (keepPayload) {
    process.env.ACTIUM_KEEP_PAYLOAD = "1";
    const archive = parsed.payloadArchive
      || (fs.existsSync(path.join(rootDir, "payload.tar.gz")) ? path.join(rootDir, "payload.tar.gz") : null);
    if (archive) {
      restorePayloadArchive(archive);
    }
    runCommand("node", ["scripts/prepare-payload.mjs", "--keep-payload"]);
  } else {
    delete process.env.ACTIUM_KEEP_PAYLOAD;
    runCommand("node", ["scripts/prepare-payload.mjs"]);
  }
  runPredeployValidations();

  console.log("\n\x1b[34m[Paso 2/3] Compilando frontend TypeScript y empaquetando assets...\x1b[0m");
  runCommand("npm", ["run", "build"]);

  console.log("\n\x1b[34m[Paso 3/3] Compilando Node Manager + Supervisor...\x1b[0m");

  const buildWindows = targetOS === "windows" || targetOS === "all";
  const buildLinux = targetOS === "linux" || targetOS === "all";

  if (buildWindows) {
    if (process.platform !== "win32") {
      console.log("\x1b[33mNota: Compilación de Windows omitida por estar en un host no-Windows.\x1b[0m");
    } else {
      console.log("\n\x1b[36mCompilando binario del Supervisor (Rust release)...\x1b[0m");
      runCommand("cargo", [
        "build",
        "--release",
        "--manifest-path",
        "src-tauri/Cargo.toml",
        "-p",
        "actium-node-supervisor",
      ]);
      stageSupervisorResources();
      if (includeTerminal) {
        console.log("\n\x1b[36mGenerando paquete de terminal del Supervisor (.zip)...\x1b[0m");
        runCommand("powershell", [
          "-NoProfile",
          "-ExecutionPolicy",
          "Bypass",
          "-File",
          "scripts/build-supervisor-windows.ps1",
        ]);
      }
      console.log("\n\x1b[36mCompilando Actium Node Manager (MSI y Setup EXE con Supervisor integrado)...\x1b[0m");
      runCommand("npm", ["run", "tauri:build"]);
    }
  }

  if (buildLinux) {
    if (process.platform === "win32") {
      console.log("\n\x1b[36mCompilando Actium Node Manager + Supervisor para Linux vía WSL Debian...\x1b[0m");
      const terminalCmd = includeTerminal
        ? "sh ./scripts/build-supervisor-linux.sh && "
        : "";
      runCommand("wsl", [
        "-d",
        "Debian",
        "--",
        "bash",
        "-lic",
        `cd /mnt/c/Dev/Workspace/ecosistema-aegis-control-local-backend/infrastructure/data-plane/installer && mkdir -p ~/.actium-tauri-target && cargo build --release --manifest-path src-tauri/Cargo.toml -p actium-node-supervisor && mkdir -p src-tauri/resources/supervisor && cp -f src-tauri/supervisor/* src-tauri/resources/supervisor/ && cp -f src-tauri/target/release/actium-node-supervisor src-tauri/resources/supervisor/actium-node-supervisor && chmod 0755 src-tauri/resources/supervisor/actium-node-supervisor src-tauri/resources/supervisor/install-supervisor-debian.sh src-tauri/resources/supervisor/postinst-debian.sh && ${terminalCmd}CARGO_TARGET_DIR=~/.actium-tauri-target npx tauri build --bundles deb && mkdir -p src-tauri/target/release/bundle/deb && cp -f ~/.actium-tauri-target/release/bundle/deb/*.deb src-tauri/target/release/bundle/deb/`,
      ], { shell: false });
      copyDebWithoutSpaces();
    } else {
      console.log("\n\x1b[36mCompilando binario del Supervisor para Linux (Rust release)...\x1b[0m");
      runCommand("cargo", [
        "build",
        "--release",
        "--manifest-path",
        "src-tauri/Cargo.toml",
        "-p",
        "actium-node-supervisor",
      ]);
      stageSupervisorResources();
      if (includeTerminal) {
        console.log("\n\x1b[36mCompilando paquete de terminal del Supervisor (.tar.gz)...\x1b[0m");
        runCommand("sh", ["./scripts/build-supervisor-linux.sh"]);
      }
      console.log("\n\x1b[36mCompilando Actium Node Manager para Linux (.deb con Supervisor integrado)...\x1b[0m");
      runCommand("npm", ["run", "tauri:build"]);
      copyDebWithoutSpaces();
    }
  }

  console.log("\n\x1b[32m===============================================================");
  console.log("   ¡COMPILACIÓN FINALIZADA CON ÉXITO!");
  console.log("===============================================================\x1b[0m");
  printCenterReleasePin();
  console.log("Ubicación de los instaladores generados:");

  const bundleDir = path.join(tauriDir, "target", "release", "bundle");
  if (!fs.existsSync(bundleDir)) return;
  for (const [label, subdir] of [
    ["Supervisor terminal", "supervisor"],
    ["Manager MSI", "msi"],
    ["Manager Setup EXE", "nsis"],
    ["Manager DEB", "deb"],
  ]) {
    const dir = path.join(bundleDir, subdir);
    if (!fs.existsSync(dir)) continue;
    console.log(`  • ${label}: \x1b[36m${dir}\x1b[0m`);
    for (const file of fs.readdirSync(dir)) {
      console.log(`    └─ ${file}`);
    }
  }
}

main().catch((err) => {
  console.error(`\n\x1b[31mError durante el proceso de compilación:\x1b[0m ${err.message}`);
  process.exit(1);
});
