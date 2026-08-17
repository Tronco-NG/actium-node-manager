import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";

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
assert.match(product, /"0\.7\.0-lab\.19"/u, "product.rs debe coincidir con el Manager Lab publicado");
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
} else {
  assert.ok(has(/\.deb$/iu), "no se genero DEB Lab");
  assert.ok(has(/\.AppImage$/iu), "no se genero AppImage Lab");
}

console.log(`Artefacto ${platform} Lab verificado: Manager ${tauriLab.version}, Runtime ${runtimeVersion}, productChannel=lab.`);
