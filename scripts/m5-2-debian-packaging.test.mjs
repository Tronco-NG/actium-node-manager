import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const tauri = JSON.parse(fs.readFileSync(path.join(root, "src-tauri/tauri.conf.json"), "utf8"));
const normalizer = fs.readFileSync(path.join(root, "scripts/normalize-debian-package.sh"), "utf8");

function toWslPath(value) {
  const normalized = path.win32.normalize(value);
  const drive = normalized.slice(0, 1).toLowerCase();
  if (!/^[a-z]$/.test(drive) || normalized[1] !== ":") {
    throw new Error(`No se pudo convertir la ruta Windows a WSL: ${value}`);
  }
  return `/mnt/${drive}${normalized.slice(2).replaceAll("\\", "/")}`;
}

function run(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8" });
  assert.equal(result.error, undefined, `${command} no pudo ejecutarse: ${result.error?.message ?? "error desconocido"}`);
  assert.equal(result.status, 0, `${command} ${args.join(" ")} fallo:\n${result.stdout}\n${result.stderr}`);
  return result.stdout.trim();
}

function debField(packagePath, field) {
  if (process.platform === "win32") {
    const distro = process.env.ACTIUM_DEB_WSL_DISTRO?.trim() || "Actium-M52";
    return run("wsl", ["-d", distro, "--", "dpkg-deb", "-f", toWslPath(packagePath), field]);
  }
  return run("dpkg-deb", ["-f", packagePath, field]);
}

function splitDepends(value) {
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => entry.split("|").map((alternative) => alternative.trim().replace(/[ (].*$/, "")));
}

function runWsl(distro, args) {
  return run("wsl", ["-d", distro, "--", ...args]);
}

function aptCandidate(distro, packageName) {
  const policy = runWsl(distro, ["apt-cache", "policy", packageName]);
  const candidate = policy.match(/^\s*Candidate:\s*(\S+)/m)?.[1];
  assert.ok(candidate, `apt-cache policy no devolvio Candidate para ${packageName} en ${distro}`);
  return candidate;
}

function distroInfo(distro) {
  const release = runWsl(distro, ["cat", "/etc/os-release"]);
  const id = release.match(/^ID=(.+)$/m)?.[1]?.replaceAll('"', "");
  const versionId = release.match(/^VERSION_ID=(.+)$/m)?.[1]?.replaceAll('"', "");
  const architecture = runWsl(distro, ["dpkg", "--print-architecture"]);
  return { id, versionId, architecture };
}

function configuredDistros() {
  return [
    ["debian12", process.env.ACTIUM_DEBIAN12_WSL_DISTRO?.trim()],
    ["debian13", process.env.ACTIUM_DEBIAN13_WSL_DISTRO?.trim()],
    ["ubuntu", process.env.ACTIUM_UBUNTU_WSL_DISTRO?.trim()],
  ].filter(([, distro]) => distro);
}

test("packaging policy uses distribution Docker packages and no obsolete names", () => {
  const depends = tauri.bundle?.linux?.deb?.depends ?? [];
  assert.ok(depends.some((value) => value.includes("docker.io") && value.includes("docker-ce")));
  assert.ok(depends.some((value) => value.includes("docker-compose") && value.includes("docker-compose-plugin")));
  assert.ok(!depends.some((value) => /docker-compose-v2/.test(value)));
  assert.match(normalizer, /libgtk-3-0 \| libgtk-3-0t64/);
  assert.match(normalizer, /if ! grep -Fq 'libgtk-3-0 \| libgtk-3-0t64'/);
  assert.doesNotMatch(normalizer, /download\.docker\.com/);
  assert.match(normalizer, /forbidden in docker-compose-v2/);
});

const debPath = process.env.ACTIUM_DEB_PATH?.trim();
test("el .deb generado declara dependencias Debian 12/13 resolubles", { skip: !debPath ? "ACTIUM_DEB_PATH no configurado" : false }, () => {
  const fields = Object.fromEntries(["Package", "Version", "Architecture", "Depends"].map((field) => [field, debField(debPath, field)]));
  assert.equal(fields.Package, "actium-node-manager");
  assert.equal(fields.Version, "0.7.0-rc.3");
  assert.equal(fields.Architecture, "amd64");

  const dependencies = splitDepends(fields.Depends);
  assert.ok(dependencies.some((entry) => entry.length === 2 && entry.includes("libgtk-3-0") && entry.includes("libgtk-3-0t64")));
  assert.ok(dependencies.some((entry) => entry.length === 2 && entry.includes("docker.io") && entry.includes("docker-ce")));
  assert.ok(dependencies.some((entry) => entry.length === 2 && entry.includes("docker-compose") && entry.includes("docker-compose-plugin")));
  assert.ok(!dependencies.flat().some((entry) => /docker-compose-v2/.test(entry)));
  assert.ok(dependencies.some((entry) => entry.includes("libwebkit2gtk-4.1-0")));
});

const distros = configuredDistros();
test("APT tiene candidatos para la matriz Debian/Ubuntu configurada", { skip: distros.length === 0 ? "No se configuraron distros WSL para la matriz" : false }, () => {
  for (const [label, distro] of distros) {
    const info = distroInfo(distro);
    assert.equal(info.architecture, "amd64", `${label} (${distro}) debe ser amd64`);
    assert.ok(["debian", "ubuntu"].includes(info.id), `${label} (${distro}) no es Debian/Ubuntu`);

    const expectedGtk = info.id === "debian" && info.versionId?.startsWith("13") ? "libgtk-3-0t64" : "libgtk-3-0";
    for (const packageName of ["docker.io", "docker-compose", "libwebkit2gtk-4.1-0", expectedGtk]) {
      assert.notEqual(aptCandidate(distro, packageName), "(none)", `${packageName} no tiene candidato en ${label}`);
    }
  }
});

test("APT simulation resolves el .deb sin instalarlo", { skip: !debPath ? "ACTIUM_DEB_PATH no configurado" : false }, () => {
  const distro = process.env.ACTIUM_DEB_WSL_DISTRO?.trim() || "Actium-M52";
  const result = spawnSync("wsl", ["-d", distro, "--", "apt-get", "--simulate", "--no-remove", "install", "-y", toWslPath(debPath)], { encoding: "utf8" });
  assert.equal(result.error, undefined, `apt-get simulation no pudo ejecutarse: ${result.error?.message ?? "error desconocido"}`);
  assert.equal(result.status, 0, `apt-get simulation fallo:\n${result.stdout}\n${result.stderr}`);
  assert.match(`${result.stdout}\n${result.stderr}`, /actium-node-manager/);
});

console.log("m5-2-debian-packaging: control DEB, matriz APT y simulacion verificados");
