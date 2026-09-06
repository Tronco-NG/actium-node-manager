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

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\\"'\\\"'")}'`;
}

function toWslPath(value) {
  const normalized = path.win32.normalize(value);
  const drive = normalized.slice(0, 1).toLowerCase();
  if (!/^[a-z]$/.test(drive) || normalized[1] !== ":") {
    throw new Error(`No se pudo convertir la ruta Windows a WSL: ${value}`);
  }
  return `/mnt/${drive}${normalized.slice(2).replaceAll("\\", "/")}`;
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
  const parsed = { os: null, terminal: null, skipPayload: true };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--os") parsed.os = argv[++i];
    if (argv[i] === "--terminal") parsed.terminal = true;
    if (argv[i] === "--no-terminal") parsed.terminal = false;
    if (argv[i] === "--skip-payload") parsed.skipPayload = true;
    if (argv[i] === "--channel" || argv[i] === "--target") i += 1;
  }
  if (argv.includes("--keep-payload") || argv.includes("--refresh-payload") || argv.includes("--payload-archive")) {
    throw new Error("M1 no acepta operaciones de payload; el snapshot se mantiene fuera del repositorio canónico.");
  }
  return parsed;
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
  console.warn("\n\x1b[33mM1: el contrato pre-deploy de Center pertenece al repositorio consumidor y no se ejecuta desde Node Manager.\x1b[0m");
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
    } finally {
      rl.close();
    }
  }

  console.log("\n\x1b[32mConfiguración:\x1b[0m");
  console.log(`  • Sistema Operativo: \x1b[35m${String(targetOS).toUpperCase()}\x1b[0m`);
  console.log("  • Producto:          \x1b[35mNODE MANAGER + SUPERVISOR\x1b[0m");
  console.log("  • Payload:           \x1b[35mfuera del repositorio; no tocar\x1b[0m");
  console.log("  • Canales:           \x1b[35mstable + lab por lugar de despliegue, no por otra release\x1b[0m");
  console.log(`  • Terminal:          \x1b[35m${includeTerminal ? "SÍ" : "NO"}\x1b[0m`);

  console.log("\n\x1b[34m[Paso 1/3] Payload externo no incluido: no se ejecuta prepare:payload ni se modifica PAYLOAD.json.\x1b[0m");
  runPredeployValidations();

  console.log("\n\x1b[34m[Paso 2/3] Compilando frontend TypeScript y empaquetando assets...\x1b[0m");
  runCommand("npm", ["run", "build"]);

  console.log("\n\x1b[34m[Paso 3/3] Compilando Node Manager + Supervisor...\x1b[0m");

  const buildWindows = targetOS === "windows" || targetOS === "all";
  const buildLinux = targetOS === "linux" || targetOS === "all";
  const payloadAvailable = fs.existsSync(path.join(tauriDir, "resources", "node", "PAYLOAD.json"));

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
      if (includeTerminal && payloadAvailable) {
        console.log("\n\x1b[36mGenerando paquete de terminal del Supervisor (.zip)...\x1b[0m");
        runCommand("powershell", [
          "-NoProfile",
          "-ExecutionPolicy",
          "Bypass",
          "-File",
          "scripts/build-supervisor-windows.ps1",
        ]);
      }
      if (payloadAvailable) {
        console.log("\n\x1b[36mCompilando Actium Node Manager (MSI y Setup EXE con Supervisor integrado)...\x1b[0m");
        runCommand("npm", ["run", "tauri:build"]);
      } else {
        console.warn("\x1b[33mM1: se omite el bundle Tauri porque resources/node/PAYLOAD.json es un artefacto externo.\x1b[0m");
      }
    }
  }

  if (buildLinux) {
    if (process.platform === "win32") {
      console.log("\n\x1b[36mCompilando Actium Node Manager + Supervisor para Linux vía WSL Debian...\x1b[0m");
      const terminalCmd = includeTerminal
        ? "sh ./scripts/build-supervisor-linux.sh && "
        : "";
      const sourceCommit = shellQuote(process.env.ACTIUM_SOURCE_COMMIT || "unknown");
      const buildId = shellQuote(process.env.ACTIUM_BUILD_ID || "unknown");
      const wslRoot = shellQuote(toWslPath(rootDir));
      const managerBuild = payloadAvailable
        ? ` && ${terminalCmd}ACTIUM_SOURCE_COMMIT=${sourceCommit} ACTIUM_BUILD_ID=${buildId} CARGO_TARGET_DIR=~/.actium-tauri-target npx tauri build --bundles deb && mkdir -p src-tauri/target/release/bundle/deb && cp -f ~/.actium-tauri-target/release/bundle/deb/*.deb src-tauri/target/release/bundle/deb/`
        : "";
      runCommand("wsl", [
        "-d",
        "Debian",
        "--",
        "bash",
        "-lic",
        `cd ${wslRoot} && mkdir -p ~/.actium-tauri-target && ACTIUM_SOURCE_COMMIT=${sourceCommit} ACTIUM_BUILD_ID=${buildId} cargo build --release --manifest-path src-tauri/Cargo.toml -p actium-node-supervisor && mkdir -p src-tauri/resources/supervisor && cp -f src-tauri/supervisor/* src-tauri/resources/supervisor/ && cp -f src-tauri/target/release/actium-node-supervisor src-tauri/resources/supervisor/actium-node-supervisor && chmod 0755 src-tauri/resources/supervisor/install-supervisor-debian.sh src-tauri/resources/supervisor/postinst-debian.sh${managerBuild}`,
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
      if (includeTerminal && payloadAvailable) {
        console.log("\n\x1b[36mCompilando paquete de terminal del Supervisor (.tar.gz)...\x1b[0m");
        runCommand("sh", ["./scripts/build-supervisor-linux.sh"]);
      }
      if (payloadAvailable) {
        console.log("\n\x1b[36mCompilando Actium Node Manager para Linux (.deb con Supervisor integrado)...\x1b[0m");
        runCommand("npm", ["run", "tauri:build"]);
        copyDebWithoutSpaces();
      } else {
        console.warn("\x1b[33mM1: se omite el bundle Tauri porque resources/node/PAYLOAD.json es un artefacto externo.\x1b[0m");
      }
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
