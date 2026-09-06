#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import {
  BUILD_MANIFEST_SCHEMA,
  architectureForTarget,
  assertBuildId,
  captureCommand,
  gitState,
  newBuildId,
  platformForTarget,
  repositoryFromOrigin,
  sha256File,
  writeJson,
} from "./release-toolkit.mjs";

const rootDir = path.resolve(import.meta.dirname, "..");
const tauriDir = path.join(rootDir, "src-tauri");
const packageMetadata = JSON.parse(fs.readFileSync(path.join(rootDir, "package.json"), "utf8"));

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

function resolveBuildIdentity(targetOS) {
  const source = gitState(rootDir);
  const configuredCommit = process.env.ACTIUM_SOURCE_COMMIT?.trim();
  if (configuredCommit && configuredCommit !== source.commit) throw new Error("BUILD_SOURCE_COMMIT_MISMATCH");
  const buildKind = (process.env.ACTIUM_BUILD_KIND || "development").trim().toLowerCase();
  if (!["development", "candidate"].includes(buildKind)) throw new Error("BUILD_KIND_INVALID");
  if (buildKind === "candidate" && source.dirty) throw new Error("BUILD_CANDIDATE_REQUIRES_CLEAN_TREE");
  const platform = platformForTarget(targetOS);
  const architecture = architectureForTarget();
  const configuredBuildId = process.env.ACTIUM_BUILD_ID?.trim();
  const buildId = configuredBuildId || newBuildId({ commit: source.commit, platform, architecture });
  assertBuildId(buildId);
  const outputDir = path.join(rootDir, "dist", "builds", buildId);
  if (fs.existsSync(outputDir)) throw new Error("BUILD_ID_ALREADY_EXISTS");
  process.env.ACTIUM_SOURCE_COMMIT = source.commit;
  process.env.ACTIUM_BUILD_ID = buildId;
  process.env.ACTIUM_BUILD_KIND = buildKind;
  process.env.ACTIUM_ALLOW_DIRTY = buildKind === "development" ? "1" : "0";
  console.log(`  • source_commit:     \x1b[35m${source.commit}\x1b[0m`);
  console.log(`  • source_dirty:      \x1b[35m${source.dirty ? "true" : "false"}\x1b[0m`);
  console.log(`  • build_kind:        \x1b[35m${buildKind}\x1b[0m`);
  console.log(`  • build_id:          \x1b[35m${buildId}\x1b[0m`);
  return { source, buildKind, buildId, platform, architecture };
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
  const parsed = { os: null, terminal: null, buildKind: null, buildId: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--os") parsed.os = argv[++i];
    if (argv[i] === "--terminal") parsed.terminal = true;
    if (argv[i] === "--no-terminal") parsed.terminal = false;
    if (argv[i] === "--build-kind") parsed.buildKind = argv[++i];
    if (argv[i] === "--build-id") parsed.buildId = argv[++i];
    if (argv[i] === "--channel" || argv[i] === "--target") throw new Error("BUILD_CHANNEL_IS_NOT_A_COMPILE_INPUT");
  }
  if (parsed.buildKind) process.env.ACTIUM_BUILD_KIND = parsed.buildKind;
  if (parsed.buildId) process.env.ACTIUM_BUILD_ID = parsed.buildId;
  return parsed;
}

function stageSupervisorResources() {
  const supervisorResDir = path.join(tauriDir, "resources", "supervisor");
  // A Linux candidate must never inherit a Windows binary or stale resource
  // from a previous build. The source of truth is src-tauri/supervisor plus
  // the binary compiled for the requested target.
  fs.rmSync(supervisorResDir, { recursive: true, force: true });
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
  console.warn("\n\x1b[33mEl build local no hace operaciones de Center, release, canal o despliegue remoto.\x1b[0m");
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

function normalizeLocalDebianPackages(testEvidence) {
  const debDir = path.join(tauriDir, "target", "release", "bundle", "deb");
  if (!fs.existsSync(debDir)) return;
  for (const name of fs.readdirSync(debDir).filter((entry) => entry.endsWith(".deb"))) {
    runBuildStep(testEvidence, "normalize_debian_package", "bash", ["scripts/normalize-debian-package.sh", path.join(debDir, name)], { shell: false });
  }
}

function runBuildStep(testEvidence, name, command, args, options = {}) {
  try {
    runCommand(command, args, options);
    testEvidence.push({ name, status: "passed", evidence: `${command} ${args.join(" ")}` });
  } catch (error) {
    testEvidence.push({ name, status: "failed", evidence: error.message });
    throw error;
  }
}

function collectArtifactFiles(platform, buildStartedAt) {
  const files = [];
  const bundleRoot = path.join(tauriDir, "target", "release", "bundle");
  const bundleDirectories = platform === "windows" ? ["nsis", "msi"] : ["deb", "appimage", "rpm"];
  const supervisorNames = platform === "windows" ? ["actium-node-supervisor.exe"] : ["actium-node-supervisor"];
  const visit = (directory) => {
    if (!fs.existsSync(directory)) return;
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const entryPath = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(entryPath);
      else if (entry.isFile() && fs.statSync(entryPath).mtimeMs >= buildStartedAt) files.push(entryPath);
    }
  };
  for (const directory of bundleDirectories) visit(path.join(bundleRoot, directory));
  for (const name of supervisorNames) {
    const binary = path.join(tauriDir, "target", "release", name);
    if (fs.existsSync(binary) && fs.statSync(binary).mtimeMs >= buildStartedAt) files.push(binary);
  }
  return [...new Set(files)];
}

function writeBuildManifest(identity, testEvidence, buildStartedAt) {
  const files = collectArtifactFiles(identity.platform, buildStartedAt);
  if (files.length === 0) throw new Error("BUILD_ARTIFACTS_MISSING");
  const buildDir = path.join(rootDir, "dist", "builds", identity.buildId);
  const artifactDir = path.join(buildDir, "artifacts");
  const contentAddressedRoot = path.join(rootDir, "dist", "artifacts", "sha256");
  const artifacts = [];
  const usedNames = new Set();
  for (const file of files) {
    const originalName = path.basename(file);
    let name = originalName.replace(/[^a-zA-Z0-9._-]/g, "-");
    if (usedNames.has(name)) name = `${path.basename(path.dirname(file))}-${name}`;
    usedNames.add(name);
    const digest = sha256File(file);
    const destination = path.join(artifactDir, name);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(file, destination);
    const contentAddressed = path.join(contentAddressedRoot, digest, name);
    fs.mkdirSync(path.dirname(contentAddressed), { recursive: true });
    if (!fs.existsSync(contentAddressed)) fs.copyFileSync(file, contentAddressed);
    artifacts.push({ name, uri: `artifacts/${name}`, sha256: digest, sizeBytes: fs.statSync(file).size });
  }
  const manifest = {
    schema: BUILD_MANIFEST_SCHEMA,
    contract: BUILD_MANIFEST_SCHEMA,
    buildId: identity.buildId,
    productId: "actium-node-manager",
    productVersion: packageMetadata.version,
    buildKind: identity.buildKind,
    sourceRepo: repositoryFromOrigin(rootDir),
    sourceCommit: identity.source.commit,
    sourceDirty: identity.source.dirty,
    platform: identity.platform,
    architecture: identity.architecture,
    toolchain: {
      node: captureCommand("node", ["--version"], rootDir),
      npm: captureCommand("npm", ["--version"], rootDir),
      cargo: captureCommand("cargo", ["--version"], rootDir),
      rustc: captureCommand("rustc", ["--version"], rootDir),
      tauri: captureCommand("npx", ["tauri", "--version"], rootDir),
    },
    artifacts,
    tests: testEvidence,
    status: "BUILT",
    createdAt: new Date().toISOString(),
  };
  writeJson(path.join(buildDir, "build-manifest.json"), manifest);
  fs.writeFileSync(path.join(buildDir, "SHA256SUMS"), `${artifacts.map((artifact) => `${artifact.sha256}  ${artifact.uri}`).join("\n")}\n`, "utf8");
  return { buildDir, manifest };
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

  const identity = resolveBuildIdentity(targetOS);
  const testEvidence = [];
  const buildStartedAt = Date.now();

  console.log("\n\x1b[32mConfiguración:\x1b[0m");
  console.log(`  • Sistema Operativo: \x1b[35m${String(targetOS).toUpperCase()}\x1b[0m`);
  console.log("  • Producto:          \x1b[35mNODE MANAGER + SUPERVISOR\x1b[0m");
  console.log("  • Base Runtime:      \x1b[35muniversal; extensiones externas\x1b[0m");
  console.log("  • Canales:           \x1b[35mse asignan después, fuera del build\x1b[0m");
  console.log(`  • Terminal legacy:   \x1b[35m${includeTerminal ? "solicitado, fuera del Base Runtime" : "NO"}\x1b[0m`);

  console.log("\n\x1b[34m[Paso 1/4] El build no genera releases, canales ni bundles de producto.\x1b[0m");
  runPredeployValidations();

  console.log("\n\x1b[34m[Paso 2/4] Compilando frontend TypeScript y empaquetando assets...\x1b[0m");
  runBuildStep(testEvidence, "frontend_build", "npm", ["run", "build"]);
  runBuildStep(testEvidence, "contract_tests", "npm", ["run", "test:contracts-m2"]);
  runBuildStep(testEvidence, "base_runtime_tests", "npm", ["run", "test:base-runtime-m2-1"]);
  runBuildStep(testEvidence, "node_core_check", "cargo", ["check", "--manifest-path", "src-tauri/Cargo.toml", "-p", "actium-node-core"]);

  console.log("\n\x1b[34m[Paso 3/4] Compilando Node Manager + Supervisor...\x1b[0m");

  const buildWindows = targetOS === "windows" || targetOS === "all";
  const buildLinux = targetOS === "linux" || targetOS === "all";

  if (buildWindows) {
    if (process.platform !== "win32") {
      console.log("\x1b[33mNota: Compilación de Windows omitida por estar en un host no-Windows.\x1b[0m");
    } else {
      console.log("\n\x1b[36mCompilando binario del Supervisor (Rust release)...\x1b[0m");
      runBuildStep(testEvidence, "supervisor_windows_build", "cargo", [
        "build",
        "--release",
        "--manifest-path",
        "src-tauri/Cargo.toml",
        "-p",
        "actium-node-supervisor",
      ]);
      stageSupervisorResources();
      console.warn("\x1b[33mEl paquete de terminal legacy no forma parte del Base Runtime; se omite.\x1b[0m");
      console.log("\n\x1b[36mCompilando Actium Node Manager Base Runtime (NSIS para RC; MSI en stable)...\x1b[0m");
      const windowsBundleArgs = packageMetadata.version.includes("-")
        ? ["run", "tauri:build", "--", "--bundles", "nsis"]
        : ["run", "tauri:build"];
      if (windowsBundleArgs.includes("nsis")) console.warn("\x1b[33mRC detectado: se construye NSIS; MSI requiere versión estable por la restricción del toolchain Wix.\x1b[0m");
      runBuildStep(testEvidence, "manager_windows_build", "npm", windowsBundleArgs);
    }
  }

  if (buildLinux) {
    if (process.platform === "win32") {
      console.log("\n\x1b[36mCompilando Actium Node Manager + Supervisor para Linux vía WSL Debian...\x1b[0m");
      console.warn("\x1b[33mEl paquete de terminal legacy no forma parte del Base Runtime; se omite.\x1b[0m");
      const sourceCommit = shellQuote(process.env.ACTIUM_SOURCE_COMMIT || "unknown");
      const buildId = shellQuote(process.env.ACTIUM_BUILD_ID || "unknown");
      const buildKind = shellQuote(process.env.ACTIUM_BUILD_KIND || "development");
      const wslRoot = shellQuote(toWslPath(rootDir));
      const managerBuild = ` && rm -rf ~/.actium-tauri-target/release/bundle/deb && mkdir -p ~/.actium-tauri-target/release/bundle/deb && ACTIUM_SOURCE_COMMIT=${sourceCommit} ACTIUM_BUILD_ID=${buildId} ACTIUM_BUILD_KIND=${buildKind} CARGO_TARGET_DIR=~/.actium-tauri-target npx tauri build --bundles deb && bash scripts/normalize-debian-package.sh ~/.actium-tauri-target/release/bundle/deb/*.deb && rm -rf src-tauri/target/release/bundle/deb && mkdir -p src-tauri/target/release/bundle/deb && cp -f ~/.actium-tauri-target/release/bundle/deb/*.deb src-tauri/target/release/bundle/deb/`;
      runBuildStep(testEvidence, "linux_supervisor_and_manager_build", "wsl", [
        "-d",
        "Debian",
        "--",
        "bash",
        "-lic",
        `cd ${wslRoot} && mkdir -p ~/.actium-tauri-target && ACTIUM_SOURCE_COMMIT=${sourceCommit} ACTIUM_BUILD_ID=${buildId} ACTIUM_BUILD_KIND=${buildKind} cargo build --release --manifest-path src-tauri/Cargo.toml -p actium-node-supervisor && rm -rf src-tauri/resources/supervisor && mkdir -p src-tauri/resources/supervisor && cp -f src-tauri/supervisor/* src-tauri/resources/supervisor/ && cp -f src-tauri/target/release/actium-node-supervisor src-tauri/resources/supervisor/actium-node-supervisor && chmod 0755 src-tauri/resources/supervisor/install-supervisor-debian.sh src-tauri/resources/supervisor/postinst-debian.sh${managerBuild}`,
      ], { shell: false });
      copyDebWithoutSpaces();
    } else {
      console.log("\n\x1b[36mCompilando binario del Supervisor para Linux (Rust release)...\x1b[0m");
      runBuildStep(testEvidence, "supervisor_linux_build", "cargo", [
        "build",
        "--release",
        "--manifest-path",
        "src-tauri/Cargo.toml",
        "-p",
        "actium-node-supervisor",
      ]);
      stageSupervisorResources();
      console.warn("\x1b[33mEl paquete de terminal legacy no forma parte del Base Runtime; se omite.\x1b[0m");
      console.log("\n\x1b[36mCompilando Actium Node Manager Base Runtime para Linux (.deb con Supervisor integrado)...\x1b[0m");
      runBuildStep(testEvidence, "manager_linux_build", "npm", ["run", "tauri:build"]);
      normalizeLocalDebianPackages(testEvidence);
      copyDebWithoutSpaces();
    }
  }

  console.log("\n\x1b[34m[Paso 4/4] Registrando build-manifest y artefactos inmutables...\x1b[0m");
  const buildOutput = writeBuildManifest(identity, testEvidence, buildStartedAt);
  console.log(`  • build-manifest:    \x1b[36m${path.join(buildOutput.buildDir, "build-manifest.json")}\x1b[0m`);
  console.log(`  • artefactos:        \x1b[36m${buildOutput.manifest.artifacts.length}\x1b[0m`);
  console.log("\n\x1b[32m===============================================================");
  console.log("   ¡COMPILACIÓN FINALIZADA CON ÉXITO!");
  console.log("===============================================================\x1b[0m");
  console.log("  Promoción:           separada; usar release:promote con un build candidate limpio.");
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
