import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const installerPath = path.join(root, "src-tauri", "supervisor", "install-supervisor-debian.sh");
const postinstPath = path.join(root, "src-tauri", "supervisor", "postinst-debian.sh");
const installer = fs.readFileSync(installerPath, "utf8");
const postinst = fs.readFileSync(postinstPath, "utf8");

function toWslPath(value) {
  const normalized = path.win32.normalize(value);
  const drive = normalized.slice(0, 1).toLowerCase();
  if (!/^[a-z]$/.test(drive) || normalized[1] !== ":") throw new Error("Ruta Windows invalida: " + value);
  return "/mnt/" + drive + normalized.slice(2).replaceAll("\\", "/");
}

function latestDeb() {
  const configured = process.env.ACTIUM_DEB_PATH?.trim();
  if (configured) return configured;
  const buildsRoot = path.join(root, "dist", "builds");
  if (!fs.existsSync(buildsRoot)) return undefined;
  const candidates = [];
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const entryPath = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(entryPath);
      else if (entry.isFile() && entry.name.endsWith(".deb")) candidates.push(entryPath);
    }
  };
  visit(buildsRoot);
  return candidates.sort((left, right) => fs.statSync(right).mtimeMs - fs.statSync(left).mtimeMs)[0];
}

function wslAvailable() {
  if (process.platform !== "win32") return false;
  const result = spawnSync("wsl", ["-l", "-q"], { encoding: "utf8" });
  return result.error === undefined && result.status === 0;
}

test("M5.3 expone preflight, backup verificable y rollback acotado", () => {
  assert.match(installer, /--preflight/);
  assert.match(installer, /--rollback/);
  assert.match(installer, /upgrade-backups/);
  assert.match(installer, /data-inventory\.sha256/);
  assert.match(installer, /state-presence/);
  assert.match(installer, /candidate_build_info="\$\("\$binary" --build-info\)/);
  assert.doesNotMatch(installer, /\$\(\$binary --build-info\)/);
  assert.doesNotMatch(installer + "\n" + postinst, /\beval\b/);
  assert.match(postinst, /--preflight --binary "\$BINARY"[\s\S]*--install --binary "\$BINARY"/);
  assert.match(installer, /cp -a -- "\$binary_target" "\$upgrade_backup_dir\/binary"/);
  assert.match(installer, /restore_upgrade_state/);
});

const debPath = latestDeb();
const integrationReady = Boolean(debPath && (process.platform !== "win32" || wslAvailable()));

test(
  "upgrade historico preserva identidad y metadata, con rollback e idempotencia en paths espaciados",
  { skip: !integrationReady ? "requiere un .deb y WSL disponible" : false },
  () => {
    const distro = process.env.ACTIUM_DEB_WSL_DISTRO?.trim() || "Actium-M52";
    const installerWsl = process.platform === "win32" ? toWslPath(installerPath) : installerPath;
    const debWsl = process.platform === "win32" ? toWslPath(debPath) : debPath;
    const script = String.raw`set -eu
installer="$1"
deb_path="$2"
work_root="$(mktemp -d '/tmp/Actium M5.3 upgrade spaces.XXXXXX')"
cleanup() { status="$?"; trap - EXIT HUP INT TERM; rm -rf -- "$work_root"; exit "$status"; }
trap cleanup EXIT HUP INT TERM
package_root="$work_root/tauri package extracted"
source_root="$work_root/installer source with spaces"
stage_root="$work_root/historical stage with spaces"
stub_dir="$work_root/mock commands with spaces"
mkdir -p "$package_root" "$source_root" "$stage_root" "$stub_dir"
dpkg-deb -x "$deb_path" "$package_root"
real_binary="$package_root/usr/lib/Actium Node Manager/supervisor/actium-node-supervisor"
test -x "$real_binary"
"$real_binary" --self-test >/dev/null
cp -- "$installer" "$source_root/install-supervisor-debian.sh"
cp -- "$package_root/usr/lib/Actium Node Manager/supervisor/actium-node-supervisor.service" "$source_root/actium-node-supervisor.service"
for template in supervisor.toml supervisor.lab.toml; do
  sed -e "s|\"/usr/lib/actium|\"$stage_root/usr/lib/actium|g" -e "s|\"/var/lib/actium|\"$stage_root/var/lib/actium|g" -e "s|\"/var/log/actium|\"$stage_root/var/log/actium|g" -e "s|\"/etc/actium|\"$stage_root/etc/actium|g" -e "s|\"/run/actium|\"$stage_root/run/actium|g" -e "s|\"/actium|\"$stage_root/actium|g" "$package_root/usr/lib/Actium Node Manager/supervisor/$template" > "$source_root/$template"
done
chmod 0755 "$source_root/install-supervisor-debian.sh"
write_stub() { target="$1"; shift; printf '%s\n' "$@" > "$target"; chmod 0755 "$target"; }
write_stub "$stub_dir/systemctl" '#!/bin/sh' 'case "$1" in' '  is-active) exit 1 ;;' '  *) exit 0 ;;' 'esac'
write_stub "$stub_dir/docker" '#!/bin/sh' '[ "$1" = compose ] && [ "$2" = version ] && exit 0' 'exit 0'
export PATH="$stub_dir:$PATH"
old_binary="$work_root/historical supervisor binary"
printf '%s\n' '#!/bin/sh' 'case "$1" in' '  --self-test) exit 0 ;;' '  --check) exit 0 ;;' '  --ping) exit 0 ;;' 'esac' 'exit 0' > "$old_binary"
chmod 0755 "$old_binary"
mkdir -p "$stage_root/usr/lib/actium/node-manager" "$stage_root/etc/actium/node-manager" "$stage_root/var/lib/actium/node-manager/identity" "$stage_root/var/lib/actium/node-manager/storage-grants" "$stage_root/var/lib/actium/node-manager/extensions" "$stage_root/etc/systemd/system" "$stage_root/actium/nodes/historical-node/state"
cp -- "$old_binary" "$stage_root/usr/lib/actium/node-manager/actium-node-supervisor"
cp -- "$source_root/actium-node-supervisor.service" "$stage_root/etc/systemd/system/actium-node-supervisor.service"
cp -- "$source_root/supervisor.toml" "$stage_root/etc/actium/node-manager/supervisor.toml"
printf '%s\n' '{"hostInstallationId":"11111111-1111-4111-8111-111111111111","hostCode":"historical-host","displayName":"Historical Host","platform":"linux","architecture":"amd64"}' > "$stage_root/var/lib/actium/node-manager/identity/host-identity.json"
printf '%s\n' '11111111-1111-4111-8111-111111111111' > "$stage_root/var/lib/actium/node-manager/host-installation-id"
printf '%s\n' '{"schemaVersion":1,"nodes":["historical-node"]}' > "$stage_root/actium/registry.json"
printf '%s\n' '{"installationId":"22222222-2222-4222-8222-222222222222","status":"running"}' > "$stage_root/actium/nodes/historical-node/.actium-node-installation.json"
printf '%s\n' '{"desiredState":"running"}' > "$stage_root/actium/nodes/historical-node/state/runtime-intent.json"
printf '%s\n' '{"grants":["historical-grant"]}' > "$stage_root/var/lib/actium/node-manager/storage-grants/grants.json"
printf '%s\n' '{"registryVersion":1,"extensions":[]}' > "$stage_root/var/lib/actium/node-manager/extensions/registry.json"
printf '%s\n' '{"legacy":true}' > "$stage_root/actium/nodes/historical-node/PAYLOAD.json"
old_digest="$(sha256sum "$stage_root/usr/lib/actium/node-manager/actium-node-supervisor" | awk '{print $1}')"
identity_digest="$(sha256sum "$stage_root/var/lib/actium/node-manager/identity/host-identity.json" | awk '{print $1}')"
installation_digest="$(sha256sum "$stage_root/var/lib/actium/node-manager/host-installation-id" | awk '{print $1}')"
registry_digest="$(sha256sum "$stage_root/actium/registry.json" | awk '{print $1}')"
node_digest="$(sha256sum "$stage_root/actium/nodes/historical-node/.actium-node-installation.json" | awk '{print $1}')"
grants_digest="$(sha256sum "$stage_root/var/lib/actium/node-manager/storage-grants/grants.json" | awk '{print $1}')"
extensions_digest="$(sha256sum "$stage_root/var/lib/actium/node-manager/extensions/registry.json" | awk '{print $1}')"
DESTDIR="$stage_root" "$source_root/install-supervisor-debian.sh" --channel stable --preflight --binary "$real_binary" >/dev/null
test ! -d "$stage_root/var/lib/actium/node-manager/upgrade-backups"
test "$(sha256sum "$stage_root/usr/lib/actium/node-manager/actium-node-supervisor" | awk '{print $1}')" = "$old_digest"
DESTDIR="$stage_root" "$source_root/install-supervisor-debian.sh" --channel stable --install --no-start --binary "$real_binary" >/dev/null
new_digest="$(sha256sum "$stage_root/usr/lib/actium/node-manager/actium-node-supervisor" | awk '{print $1}')"
test "$new_digest" != "$old_digest"
test "$(sha256sum "$stage_root/var/lib/actium/node-manager/identity/host-identity.json" | awk '{print $1}')" = "$identity_digest"
test "$(sha256sum "$stage_root/var/lib/actium/node-manager/host-installation-id" | awk '{print $1}')" = "$installation_digest"
test "$(sha256sum "$stage_root/actium/registry.json" | awk '{print $1}')" = "$registry_digest"
test "$(sha256sum "$stage_root/actium/nodes/historical-node/.actium-node-installation.json" | awk '{print $1}')" = "$node_digest"
test "$(sha256sum "$stage_root/var/lib/actium/node-manager/storage-grants/grants.json" | awk '{print $1}')" = "$grants_digest"
test "$(sha256sum "$stage_root/var/lib/actium/node-manager/extensions/registry.json" | awk '{print $1}')" = "$extensions_digest"
manifest_path="$(find "$stage_root/var/lib/actium/node-manager/upgrade-backups" -mindepth 2 -maxdepth 2 -type f -name manifest | sort | tail -n 1)"
backup_dir="$(dirname -- "$manifest_path")"
test -n "$backup_dir"
test -f "$backup_dir/binary"
test -f "$backup_dir/state-files/host-installation-id"
test -f "$backup_dir/state-files/storage-grants/grants.json"
test -f "$backup_dir/state-files/extensions/registry.json"
test -f "$backup_dir/data-inventory.sha256"
test -f "$backup_dir/state-inventory.sha256"
grep -Fq 'grants.json' "$backup_dir/state-inventory.sha256"
grep -Fq 'registry.json' "$backup_dir/state-inventory.sha256"
! grep -Fq 'PAYLOAD.json' "$backup_dir/data-inventory.sha256"
DESTDIR="$stage_root" "$source_root/install-supervisor-debian.sh" --rollback "$backup_dir" >/dev/null
test "$(sha256sum "$stage_root/usr/lib/actium/node-manager/actium-node-supervisor" | awk '{print $1}')" = "$old_digest"
test "$(sha256sum "$stage_root/var/lib/actium/node-manager/identity/host-identity.json" | awk '{print $1}')" = "$identity_digest"
test "$(sha256sum "$stage_root/var/lib/actium/node-manager/host-installation-id" | awk '{print $1}')" = "$installation_digest"
test "$(sha256sum "$stage_root/actium/registry.json" | awk '{print $1}')" = "$registry_digest"
test "$(sha256sum "$stage_root/actium/nodes/historical-node/.actium-node-installation.json" | awk '{print $1}')" = "$node_digest"
test "$(sha256sum "$stage_root/var/lib/actium/node-manager/storage-grants/grants.json" | awk '{print $1}')" = "$grants_digest"
test "$(sha256sum "$stage_root/var/lib/actium/node-manager/extensions/registry.json" | awk '{print $1}')" = "$extensions_digest"
DESTDIR="$stage_root" "$source_root/install-supervisor-debian.sh" --channel stable --install --no-start --binary "$real_binary" >/dev/null
DESTDIR="$stage_root" "$source_root/install-supervisor-debian.sh" --channel stable --install --no-start --binary "$real_binary" >/dev/null
test "$(sha256sum "$stage_root/usr/lib/actium/node-manager/actium-node-supervisor" | awk '{print $1}')" = "$new_digest"
test "$(sha256sum "$stage_root/var/lib/actium/node-manager/identity/host-identity.json" | awk '{print $1}')" = "$identity_digest"
test "$(sha256sum "$stage_root/var/lib/actium/node-manager/host-installation-id" | awk '{print $1}')" = "$installation_digest"
test "$(sha256sum "$stage_root/actium/registry.json" | awk '{print $1}')" = "$registry_digest"
test "$(sha256sum "$stage_root/actium/nodes/historical-node/.actium-node-installation.json" | awk '{print $1}')" = "$node_digest"
test "$(sha256sum "$stage_root/var/lib/actium/node-manager/storage-grants/grants.json" | awk '{print $1}')" = "$grants_digest"
test "$(sha256sum "$stage_root/var/lib/actium/node-manager/extensions/registry.json" | awk '{print $1}')" = "$extensions_digest"
printf '%s\n' 'm5-3 upgrade compatibility: PASS'
`;
    const args = process.platform === "win32"
      ? ["-d", distro, "--user", "root", "--", "bash", "-s", "--", installerWsl, debWsl]
      : ["bash", "-s", "--", installerWsl, debWsl];
    const command = process.platform === "win32" ? "wsl" : "bash";
    const result = spawnSync(command, args, { encoding: "utf8", input: script, maxBuffer: 3 * 1024 * 1024 });
    assert.equal(result.error, undefined, command + " no pudo ejecutarse: " + (result.error?.message ?? "error desconocido"));
    assert.equal(result.status, 0, "compatibilidad de upgrade fallo:\n" + result.stdout + "\n" + result.stderr);
    assert.match(result.stdout, /m5-3 upgrade compatibility: PASS/);
  },
);

console.log("m5-3-upgrade-compatibility: preflight, backup, rollback e idempotencia verificados");
