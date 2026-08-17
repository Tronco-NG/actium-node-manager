import assert from "node:assert/strict";
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import process from "node:process";
import { escapeRegExp } from "./escape-regexp.mjs";

const installerRoot = resolve(import.meta.dirname, "..");
const dataPlaneRoot = resolve(installerRoot, "..");
const args = process.argv.slice(2);
const valueFor = (name) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};
const platform = valueFor("--platform");
const bundleRoot = resolve(installerRoot, valueFor("--bundle-root") ?? "src-tauri/target/release/bundle");

if (!['windows', 'linux'].includes(platform)) {
  throw new Error("Uso: node scripts/verify-lab-artifact.mjs --platform <windows|linux> [--bundle-root <ruta>]");
}

const runtimeVersion = readFileSync(resolve(dataPlaneRoot, "VERSION"), "utf8").trim();
const payload = JSON.parse(readFileSync(resolve(installerRoot, "src-tauri/resources/node/PAYLOAD.json"), "utf8"));
const tauriLab = JSON.parse(readFileSync(resolve(installerRoot, "src-tauri/tauri.lab.conf.json"), "utf8"));
const product = readFileSync(resolve(installerRoot, "src-tauri/src/product.rs"), "utf8");
const paths = readFileSync(resolve(installerRoot, "src-tauri/src/paths.rs"), "utf8");
const supervisorLab = readFileSync(resolve(installerRoot, "src-tauri/supervisor/supervisor.lab.toml"), "utf8");

assert.match(runtimeVersion, /^0\.8\.0-lab\.\d+$/u, "VERSION debe ser un candidato Lab");
assert.equal(payload.schema, 3, "el payload Lab debe usar schema 3");
assert.equal(payload.productChannel, "lab", "el payload generado debe declarar productChannel=lab");
assert.equal(payload.releaseVersion, runtimeVersion, "payload y VERSION Lab deben coincidir");
assert.equal(payload.sourceDirty, false, "un artefacto publicable exige sourceDirty=false");
assert.equal(tauriLab.identifier, "com.actium.node-manager.lab", "identifier Lab incorrecto");
assert.equal(tauriLab.productName, "Actium Node Manager Lab", "nombre visible Lab incorrecto");
assert.match(tauriLab.version, /^0\.7\.0-lab\.\d+$/u, "Manager Lab debe usar version Lab");
assert.match(tauriLab.bundle?.windows?.wix?.version ?? "", /^\d+\.\d+\.\d+(?:\.\d+)?$/u, "MSI Lab debe usar version Windows numerica");
assert.match(product, /pub const PRODUCT_CHANNEL: &str = if cfg!\(actium_channel_lab\) \{\s*"lab"/u, "el binario debe compilar el canal Lab");
assert.match(product, new RegExp(`"${escapeRegExp(tauriLab.version)}"`, "u"), "product.rs debe coincidir con el Manager Lab publicado");
if (process.env.GITHUB_SHA) {
  assert.equal(payload.sourceCommit, process.env.GITHUB_SHA, "sourceCommit del payload debe ser GITHUB_SHA");
}
assert.match(paths, /node-manager-lab/u, "las rutas Linux Lab deben permanecer aisladas");
assert.match(paths, /NodeManagerLab/u, "las rutas Windows Lab deben permanecer aisladas");
assert.match(supervisorLab, /^product_channel = "lab"$/mu, "Supervisor debe declarar canal Lab");
assert.match(supervisorLab, /authorized_nodes_root = "\/srv\/actium-lab\/nodes"/u, "raiz Linux Lab incorrecta");

function collectFiles(root) {
  if (!existsSync(root)) return [];
  return readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
    const path = resolve(root, entry.name);
    return entry.isDirectory() ? collectFiles(path) : [path];
  });
}

const files = collectFiles(bundleRoot);
const has = (pattern) => files.some((file) => pattern.test(file));
if (platform === "windows") {
  assert.ok(has(/\.exe$/iu), "no se genero NSIS Lab (.exe)");
  assert.ok(has(/\.msi$/iu), "no se genero MSI Lab (.msi)");
  const msi = files.find((file) => /\.msi$/iu.test(file));
  inspectWindowsMsi(msi, tauriLab, payload);
  const nsis = files.find((file) => /\.exe$/iu.test(file));
  inspectWindowsNsis(nsis, tauriLab, payload);
} else {
  assert.ok(has(/\.deb$/iu), "no se genero DEB Lab");
  assert.ok(has(/\.AppImage$/iu), "no se genero AppImage Lab");
  const deb = files.find((file) => /\.deb$/iu.test(file));
  inspectLinuxDeb(deb, tauriLab, payload);
  const appImage = files.find((file) => /\.AppImage$/iu.test(file));
  inspectLinuxAppImage(appImage, payload);
}

const supervisorDir = resolve(bundleRoot, "supervisor");
assert.ok(existsSync(supervisorDir), "el release set debe incluir el artefacto Supervisor");
const supervisorFiles = collectFiles(supervisorDir);
assert.ok(
  supervisorFiles.some((file) => /actium-node-supervisor-0\.5\.10/u.test(file)),
  "el release set debe incluir Supervisor 0.5.10",
);
inspectSupervisorPayload(supervisorFiles, payload, product);

console.log(`Artefacto ${platform} Lab verificado: Manager ${tauriLab.version}, Runtime ${runtimeVersion}, productChannel=lab, sourceCommit=${payload.sourceCommit}.`);

function inspectLinuxDeb(debPath, lab, payloadManifest) {
  if (!debPath || !existsSync(debPath)) throw new Error("DEB Lab ausente");
  const control = spawnSync("dpkg-deb", ["-f", debPath, "Package", "Version", "Architecture"], { encoding: "utf8" });
  if (control.status !== 0) throw new Error(`dpkg-deb -f fallo: ${control.stderr}`);
  const fields = Object.fromEntries(
    control.stdout
      .split(/\r?\n/u)
      .map((line) => line.split(/:\s+/u))
      .filter((pair) => pair.length >= 2)
      .map(([key, ...rest]) => [key.trim().toLowerCase(), rest.join(": ").trim()]),
  );
  const expectedPackage = String(lab.productName).toLowerCase().replace(/\s+/gu, "-");
  assert.equal(fields.package, expectedPackage, `Package DEB exacto: ${control.stdout}`);
  assert.equal(fields.version, lab.version, `Version DEB exacta: ${control.stdout}`);
  assert.match(fields.architecture ?? "", /^(amd64|arm64)$/u, `Architecture DEB: ${control.stdout}`);
  const extractRoot = join(tmpdir(), `actium-deb-${process.pid}`);
  rmSync(extractRoot, { recursive: true, force: true });
  mkdirSync(extractRoot, { recursive: true });
  const extracted = spawnSync("dpkg-deb", ["-x", debPath, extractRoot], { encoding: "utf8" });
  if (extracted.status !== 0) throw new Error(`dpkg-deb -x fallo: ${extracted.stderr}`);
  const embedded = collectFiles(extractRoot).find((file) => file.endsWith("PAYLOAD.json"));
  assertEmbeddedPayload(embedded, payloadManifest, "DEB");
  rmSync(extractRoot, { recursive: true, force: true });
}

function inspectWindowsMsi(msiPath, lab, payloadManifest) {
  if (!msiPath || !existsSync(msiPath)) throw new Error("MSI Lab ausente");
  assert.equal(lab.bundle?.windows?.wix?.version, "0.7.0.22");
  assert.equal(lab.productName, "Actium Node Manager Lab");
  assert.equal(lab.identifier, "com.actium.node-manager.lab");
  assert.equal(payloadManifest.productChannel, "lab");
  const extractRoot = join(tmpdir(), `actium-msi-${process.pid}`);
  rmSync(extractRoot, { recursive: true, force: true });
  mkdirSync(extractRoot, { recursive: true });
  const extracted = extractWindowsBundle(msiPath, extractRoot, "MSI");
  const inventory = collectFiles(extractRoot);
  assert.ok(inventory.length > 0, "MSI no inventario contenido real");
  const product = extracted.product ?? {};
  if (product.ProductName) {
    assert.match(product.ProductName, /Actium Node Manager Lab/u);
  }
  if (product.ProductVersion) {
    assert.equal(product.ProductVersion, lab.bundle.windows.wix.version);
  }
  const embedded = inventory.find((file) => /PAYLOAD\.json$/iu.test(file));
  if (!embedded) {
    throw new Error(
      `MSI extraido sin PAYLOAD.json. Inventario=${inventory.slice(0, 40).join(" | ")}`,
    );
  }
  assertEmbeddedPayload(embedded, payloadManifest, "MSI");
  rmSync(extractRoot, { recursive: true, force: true });
}

function inspectWindowsNsis(exePath, lab, payloadManifest) {
  if (!exePath || !existsSync(exePath)) throw new Error("NSIS Lab ausente");
  assert.match(exePath, /Actium Node Manager Lab|actium-node-manager/iu);
  const extractRoot = join(tmpdir(), `actium-nsis-${process.pid}`);
  rmSync(extractRoot, { recursive: true, force: true });
  mkdirSync(extractRoot, { recursive: true });
  extractWindowsBundle(exePath, extractRoot, "NSIS");
  const embedded = collectFiles(extractRoot).find((file) => file.endsWith("PAYLOAD.json"));
  assertEmbeddedPayload(embedded, payloadManifest, "NSIS");
  assert.match(lab.version, /^0\.7\.0-lab\.22$/u);
  rmSync(extractRoot, { recursive: true, force: true });
}

function extractWindowsBundle(bundlePath, extractRoot, label) {
  const product = {};
  if (process.platform === "win32") {
    const escaped = bundlePath.replaceAll("'", "''");
    const script = [
      `$installer = New-Object -ComObject WindowsInstaller.Installer`,
      `if ('${label}' -eq 'MSI') {`,
      `  $db = $installer.OpenDatabase('${escaped}', 0)`,
      `  function Prop([string]$name) { $v = $db.OpenView(\"SELECT \`Value\` FROM Property WHERE \`Property\` = '$name'\"); $v.Execute(); $r = $v.Fetch(); if ($r) { $r.StringData(1) } }`,
      `  Write-Output (\"ProductName=\" + (Prop 'ProductName'))`,
      `  Write-Output (\"ProductVersion=\" + (Prop 'ProductVersion'))`,
      `}`,
    ].join("; ");
    const props = spawnSync("powershell", ["-NoProfile", "-Command", script], { encoding: "utf8" });
    if (props.status === 0) {
      for (const line of props.stdout.split(/\r?\n/u)) {
        const index = line.indexOf("=");
        if (index > 0) product[line.slice(0, index)] = line.slice(index + 1).trim();
      }
    }
  }
  let extracted = false;
  if (label === "MSI" && process.platform === "win32") {
    const admin = spawnSync("msiexec", ["/a", bundlePath, "/qn", `TARGETDIR=${extractRoot}`], {
      encoding: "utf8",
    });
    extracted = admin.status === 0;
    if (!extracted) {
      throw new Error(`msiexec /a fallo: ${admin.stderr || admin.stdout || admin.status}`);
    }
  } else {
    const sevenZip = ["7z", "7za", "C:\\\\Program Files\\\\7-Zip\\\\7z.exe"];
    for (const bin of sevenZip) {
      const result = spawnSync(bin, ["x", `-o${extractRoot}`, "-y", bundlePath], { encoding: "utf8" });
      if (result.status === 0) {
        extracted = true;
        break;
      }
    }
  }
  if (!extracted) {
    throw new Error(`${label} no se pudo extraer para inspeccionar payload e identidad`);
  }
  return { product };
}

function assertEmbeddedPayload(embeddedPath, payloadManifest, label) {
  assert.ok(embeddedPath, `${label} debe embeber PAYLOAD.json`);
  const embeddedPayload = JSON.parse(readFileSync(embeddedPath, "utf8"));
  assert.equal(embeddedPayload.releaseVersion, payloadManifest.releaseVersion, `${label} releaseVersion`);
  assert.equal(embeddedPayload.productChannel, "lab", `${label} productChannel`);
  assert.equal(embeddedPayload.sourceCommit, payloadManifest.sourceCommit, `${label} sourceCommit`);
  assert.equal(embeddedPayload.sourceDirty, false, `${label} sourceDirty`);
  assert.equal(embeddedPayload.treeSha256, payloadManifest.treeSha256, `${label} treeSha256`);
}

function inspectLinuxAppImage(appImagePath, payloadManifest) {
  if (!appImagePath || !existsSync(appImagePath)) throw new Error("AppImage Lab ausente");
  const extractRoot = join(tmpdir(), `actium-appimage-${process.pid}`);
  rmSync(extractRoot, { recursive: true, force: true });
  mkdirSync(extractRoot, { recursive: true });
  const extracted = spawnSync(appImagePath, ["--appimage-extract"], {
    cwd: extractRoot,
    encoding: "utf8",
    env: { ...process.env, APPIMAGE_EXTRACT_AND_RUN: "1" },
  });
  if (extracted.status !== 0) {
    throw new Error(`AppImage extract fallo: ${extracted.stderr || extracted.stdout}`);
  }
  const embedded = collectFiles(extractRoot).find((file) => file.endsWith("PAYLOAD.json"));
  assertEmbeddedPayload(embedded, payloadManifest, "AppImage");
  rmSync(extractRoot, { recursive: true, force: true });
}

function inspectSupervisorPayload(supervisorFiles, payloadManifest, productSource) {
  const archive = supervisorFiles.find((file) =>
    /actium-node-supervisor-0\.5\.10/u.test(file) && /\.(?:tar\.gz|tgz|zip)$/iu.test(file),
  );
  if (!archive) {
    throw new Error("artefacto Supervisor 0.5.10 ausente o no extraible");
  }
  const extractRoot = join(tmpdir(), `actium-supervisor-${process.pid}`);
  rmSync(extractRoot, { recursive: true, force: true });
  mkdirSync(extractRoot, { recursive: true });
  const extracted = spawnSync("tar", ["-xf", archive, "-C", extractRoot], { encoding: "utf8" });
  if (extracted.status !== 0) {
    throw new Error(`No se pudo extraer el artefacto Supervisor: ${extracted.stderr}`);
  }
  const files = collectFiles(extractRoot);
  const readme = files.find((file) => file.endsWith("README.md"));
  const labToml = files.find((file) => file.endsWith("supervisor.lab.toml"));
  assert.ok(readme, "Supervisor debe incluir README");
  assert.match(readFileSync(readme, "utf8"), /Actium Node Supervisor 0\.5\.10/u);
  assert.ok(labToml, "Supervisor debe incluir supervisor.lab.toml");
  assert.match(readFileSync(labToml, "utf8"), /product_channel = "lab"/u);
  assert.match(productSource, /NODE_SUPERVISOR_VERSION: &str = "0\.5\.10"/u);
  const ipc = readFileSync(resolve(installerRoot, "src-tauri/actium-node-core/src/ipc.rs"), "utf8");
  assert.match(ipc, /SUPERVISOR_VERSION: &str = "0\.5\.10"/u);
  assert.match(ipc, /host_identity_v1/u);
  assert.match(ipc, /capability_scoped_config/u);
  assert.match(ipc, /IPC_PROTOCOL_VERSION: u16 = 3/u);
  const embedded = files.find((file) => file.endsWith("PAYLOAD.json"));
  assertEmbeddedPayload(embedded, payloadManifest, "Supervisor");
  rmSync(extractRoot, { recursive: true, force: true });
}
