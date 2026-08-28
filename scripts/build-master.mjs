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

async function main() {
  console.log("\x1b[32m===============================================================");
  console.log("   ACTIUM COMPILADOR MAESTRO Y GENERADOR DE INSTALADORES");
  console.log("===============================================================\x1b[0m");

  const args = process.argv.slice(2);
  let targetOS = null;
  let targetArtifact = null;
  let targetChannel = null;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--os") targetOS = args[++i];
    if (args[i] === "--target") targetArtifact = args[++i];
    if (args[i] === "--channel") targetChannel = args[++i];
  }

  const isInteractive = !targetOS || !targetArtifact || !targetChannel;

  if (isInteractive) {
    const rl = readline.createInterface({ input, output });
    try {
      if (!targetOS) {
        targetOS = await askQuestion(rl, "1. ¿Para qué Sistema Operativo deseas compilar?", [
          { label: `Windows (${process.platform === "win32" ? "Host actual" : "x86_64"})`, value: "windows" },
          { label: "Linux (Debian / Ubuntu / Bash scripts / .deb)", value: "linux" },
          { label: "Ambos (Windows + Linux en paralelo)", value: "all" },
        ], process.platform === "win32" ? 0 : 1);
      }

      if (!targetArtifact) {
        targetArtifact = await askQuestion(rl, "2. ¿Qué componente deseas compilar y empaquetar?", [
          { label: "Supervisor Autónomo / Instalador de Servicio (.exe / .sh / .tar.gz)", value: "supervisor" },
          { label: "Actium Node Manager GUI (.exe / .msi / .deb)", value: "manager" },
          { label: "Todo el Ecosistema Completo (Supervisor Autónomo + Manager GUI)", value: "all" },
        ], 2);
      }

      if (!targetChannel) {
        targetChannel = await askQuestion(rl, "3. ¿Qué canal / preset de aprovisionamiento deseas configurar?", [
          { label: "Dual-Channel (Ambos: Producción Stable 8xxx + Laboratorio Lab 18xxx)", value: "both" },
          { label: "Laboratorio (Lab / Staging - puertos 18xxx)", value: "lab" },
          { label: "Producción (Stable - puertos 8xxx)", value: "stable" },
        ], 0);
      }
    } finally {
      rl.close();
    }
  }

  console.log("\n\x1b[32mConfiguración de compilación seleccionada:\x1b[0m");
  console.log(`  • Sistema Operativo: \x1b[35m${targetOS.toUpperCase()}\x1b[0m`);
  console.log(`  • Componente:       \x1b[35m${targetArtifact.toUpperCase()}\x1b[0m`);
  console.log(`  • Canal / Preset:   \x1b[35m${targetChannel.toUpperCase()}\x1b[0m`);

  // Paso 1: Preparar payload
  console.log("\n\x1b[34m[Paso 1/3] Preparando y validando el payload de contratos...\x1b[0m");
  runCommand("node", ["scripts/prepare-payload.mjs"]);

  // Paso 2: Compilación de Frontend si se compila Manager GUI
  if (targetArtifact === "manager" || targetArtifact === "all") {
    console.log("\n\x1b[34m[Paso 2/3] Compilando frontend TypeScript y empaquetando assets...\x1b[0m");
    runCommand("npm", ["run", "build"]);
  }

  // Paso 3: Compilación de artefactos
  console.log("\n\x1b[34m[Paso 3/3] Compilando binarios e instaladores nativos...\x1b[0m");

  const buildWindows = targetOS === "windows" || targetOS === "all";
  const buildLinux = targetOS === "linux" || targetOS === "all";

  // --- Windows Builds ---
  if (buildWindows) {
    if (process.platform !== "win32") {
      console.log("\x1b[33mNota: Compilación de Windows omitida por estar en entorno host no-Windows.\x1b[0m");
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

      // Preparar recursos de supervisor para ser embebidos en el paquete Tauri
      const supervisorResDir = path.join(tauriDir, "resources", "supervisor");
      fs.mkdirSync(supervisorResDir, { recursive: true });
      const supervisorSrcDir = path.join(tauriDir, "supervisor");
      if (fs.existsSync(supervisorSrcDir)) {
        fs.cpSync(supervisorSrcDir, supervisorResDir, { recursive: true });
      }
      const supervisorExe = path.join(tauriDir, "target", "release", "actium-node-supervisor.exe");
      if (fs.existsSync(supervisorExe)) {
        fs.copyFileSync(supervisorExe, path.join(supervisorResDir, "actium-node-supervisor.exe"));
      }

      if (targetArtifact === "supervisor" || targetArtifact === "all") {
        console.log("\n\x1b[36mGenerando paquete distribuible del Supervisor (.zip autónomo con scripts)...\x1b[0m");
        const channelFlag = targetChannel === "both" ? "lab" : targetChannel;
        runCommand("powershell", [
          "-NoProfile",
          "-ExecutionPolicy",
          "Bypass",
          "-File",
          "scripts/build-supervisor-windows.ps1",
          "-Channel",
          channelFlag,
        ]);
      }

      if (targetArtifact === "manager" || targetArtifact === "all") {
        console.log("\n\x1b[36mCompilando Actium Node Manager (MSI y Setup EXE con Supervisor integrado)...\x1b[0m");
        runCommand("npm", ["run", "tauri:build"]);
      }
    }
  }

  // --- Linux Builds ---
  if (buildLinux) {
    if (process.platform === "win32") {
      if (targetArtifact === "supervisor" || targetArtifact === "all") {
        console.log("\n\x1b[36mCompilando Actium Node Supervisor para Linux vía WSL (Debian / Ubuntu / Bash)...\x1b[0m");
        try {
          runCommand("node", ["scripts/build-supervisor-linux.mjs"]);
        } catch (err) {
          console.log(`\x1b[33mWSL build aviso: ${err.message}\x1b[0m`);
        }
      }
      if (targetArtifact === "manager" || targetArtifact === "all") {
        console.log("\n\x1b[36mCompilando Actium Node Manager para Linux (.deb bundle vía WSL Debian)...\x1b[0m");
        try {
          const debOut = path.join(tauriDir, "target", "release", "bundle", "deb");
          if (!fs.existsSync(debOut)) fs.mkdirSync(debOut, { recursive: true });
          runCommand("wsl", [
            "-d",
            "Debian",
            "--",
            "bash",
            "-lic",
            "cd /mnt/c/Dev/Workspace/ecosistema-aegis-control-local-backend/infrastructure/data-plane/installer && rm -rf /var/tmp/actium-tauri-target && CARGO_TARGET_DIR=/var/tmp/actium-tauri-target npx tauri build --bundles deb && cp -f /var/tmp/actium-tauri-target/release/bundle/deb/*.deb src-tauri/target/release/bundle/deb/",
          ]);
        } catch (err) {
          console.log(`\x1b[33mWSL Debian build aviso: ${err.message}\x1b[0m`);
        }
      }
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

      // Preparar recursos de supervisor para ser embebidos en el paquete Tauri
      const supervisorResDir = path.join(tauriDir, "resources", "supervisor");
      fs.mkdirSync(supervisorResDir, { recursive: true });
      const supervisorSrcDir = path.join(tauriDir, "supervisor");
      if (fs.existsSync(supervisorSrcDir)) {
        fs.cpSync(supervisorSrcDir, supervisorResDir, { recursive: true });
      }
      const supervisorBin = path.join(tauriDir, "target", "release", "actium-node-supervisor");
      if (fs.existsSync(supervisorBin)) {
        fs.copyFileSync(supervisorBin, path.join(supervisorResDir, "actium-node-supervisor"));
        fs.chmodSync(path.join(supervisorResDir, "actium-node-supervisor"), 0o755);
      }
      const installScript = path.join(supervisorResDir, "install-supervisor-debian.sh");
      if (fs.existsSync(installScript)) {
        fs.chmodSync(installScript, 0o755);
      }
      const postinstScript = path.join(supervisorResDir, "postinst-debian.sh");
      if (fs.existsSync(postinstScript)) {
        fs.chmodSync(postinstScript, 0o755);
      }

      if (targetArtifact === "supervisor" || targetArtifact === "all") {
        console.log("\n\x1b[36mCompilando Actium Node Supervisor para Linux (.tar.gz + instalador interactivo)...\x1b[0m");
        runCommand("sh", ["./scripts/build-supervisor-linux.sh"]);
      }
      if (targetArtifact === "manager" || targetArtifact === "all") {
        console.log("\n\x1b[36mCompilando Actium Node Manager para Linux (.deb bundle con Supervisor integrado)...\x1b[0m");
        runCommand("npm", ["run", "tauri:build"]);
      }
    }
  }

  console.log("\n\x1b[32m===============================================================");
  console.log("   ¡COMPILACIÓN FINALIZADA CON ÉXITO!");
  console.log("===============================================================\x1b[0m");
  console.log("Ubicación de los instaladores generados:");

  const bundleDir = path.join(tauriDir, "target", "release", "bundle");
  if (fs.existsSync(bundleDir)) {
    const supervisorBundle = path.join(bundleDir, "supervisor");
    if (fs.existsSync(supervisorBundle)) {
      console.log(`  • Supervisor Packages: \x1b[36m${supervisorBundle}\x1b[0m`);
      fs.readdirSync(supervisorBundle).forEach((file) => {
        console.log(`    └─ ${file}`);
      });
    }
    const msiBundle = path.join(bundleDir, "msi");
    if (fs.existsSync(msiBundle)) {
      console.log(`  • Manager MSI: \x1b[36m${msiBundle}\x1b[0m`);
      fs.readdirSync(msiBundle).forEach((file) => {
        console.log(`    └─ ${file}`);
      });
    }
    const nsisBundle = path.join(bundleDir, "nsis");
    if (fs.existsSync(nsisBundle)) {
      console.log(`  • Manager Setup EXE: \x1b[36m${nsisBundle}\x1b[0m`);
      fs.readdirSync(nsisBundle).forEach((file) => {
        console.log(`    └─ ${file}`);
      });
    }
    const debBundle = path.join(bundleDir, "deb");
    if (fs.existsSync(debBundle)) {
      console.log(`  • Manager DEB: \x1b[36m${debBundle}\x1b[0m`);
      fs.readdirSync(debBundle).forEach((file) => {
        console.log(`    └─ ${file}`);
      });
    }
  }
}

main().catch((err) => {
  console.error(`\n\x1b[31mError durante el proceso de compilación:\x1b[0m ${err.message}`);
  process.exit(1);
});
