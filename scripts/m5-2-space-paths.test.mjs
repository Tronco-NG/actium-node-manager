import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const installerPath = path.join(root, "src-tauri", "supervisor", "install-supervisor-debian.sh");
const postinstPath = path.join(root, "src-tauri", "supervisor", "postinst-debian.sh");
const stagingScriptPath = path.join(root, "scripts", "build-supervisor-linux.sh");
const installer = fs.readFileSync(installerPath, "utf8");
const postinst = fs.readFileSync(postinstPath, "utf8");
const stagingScript = fs.readFileSync(stagingScriptPath, "utf8");

function toWslPath(value) {
  const normalized = path.win32.normalize(value);
  const drive = normalized.slice(0, 1).toLowerCase();
  if (!/^[a-z]$/.test(drive) || normalized[1] !== ":") {
    throw new Error("No se pudo convertir la ruta Windows a WSL: " + value);
  }
  return "/mnt/" + drive + normalized.slice(2).replaceAll("\\", "/");
}

function latestDeb() {
  const configured = process.env.ACTIUM_DEB_PATH?.trim();
  if (configured) return configured;

  const candidates = [];
  const buildsRoot = path.join(root, "dist", "builds");
  if (!fs.existsSync(buildsRoot)) return undefined;
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

test("Debian scripts quote binary and filesystem paths without eval or command strings", () => {
  assert.match(installer, /build_identity="\$\("\$binary" --build-info\)/);
  assert.doesNotMatch(installer, /build_identity="\(\$binary --build-info\)/);
  assert.match(installer, /root_prefix="\$\{DESTDIR:-\}"/);
  assert.match(installer, /install -d -m 0755 "\$config_dir" "\$lib_dir" "\$doc_dir"/);
  assert.match(installer, /cp -a -- "\$config_path" "\$backup_dir\/supervisor\.toml"/);
  assert.match(installer, /mv -- "\$binary_next" "\$binary_target"/);
  assert.match(installer, /test -S "\$socket_path"/);
  assert.match(installer, /"\$binary_target" --config "\$config_path" --ping/);
  assert.doesNotMatch(installer + "\n" + postinst + "\n" + stagingScript, /\beval\b/);
  assert.match(postinst, /"\$SCRIPT" --channel "\$CHANNEL" --install --binary "\$BINARY"/);
  assert.match(stagingScript, /install -m 0755 "\$tauri_root\/target\/release\/actium-node-supervisor"/);
});

const debPath = latestDeb();
const integrationReady = Boolean(debPath && (process.platform !== "win32" || wslAvailable()));

test(
  "instalador Debian funciona con el path real Tauri y staging/rollback con espacios",
  { skip: !integrationReady ? "requiere un .deb y WSL disponible" : false },
  () => {
    const distro = process.env.ACTIUM_DEB_WSL_DISTRO?.trim() || "Actium-M52";
    const installerWsl = process.platform === "win32" ? toWslPath(installerPath) : installerPath;
    const debWsl = process.platform === "win32" ? toWslPath(debPath) : debPath;
    const script = String.raw`set -eu
installer="$1"
deb_path="$2"
work_root="$(mktemp -d '/tmp/Actium M5.2 spaces.XXXXXX')"
created_group=0

cleanup() {
  status="$?"
  trap - EXIT HUP INT TERM
  if [ "$created_group" -eq 1 ]; then
    groupdel actium-node-operators >/dev/null 2>&1 || true
  fi
  rm -rf -- "$work_root"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

if ! getent group actium-node-operators >/dev/null 2>&1; then
  groupadd --system actium-node-operators
  created_group=1
fi

package_root="$work_root/tauri package extracted"
source_root="$work_root/installer source with spaces"
stage_root="$work_root/staged root with spaces"
stub_dir="$work_root/mock commands with spaces"
mkdir -p "$package_root" "$source_root" "$stage_root" "$stub_dir"
dpkg-deb -x "$deb_path" "$package_root"

real_binary="$package_root/usr/lib/Actium Node Manager/supervisor/actium-node-supervisor"
real_installer="$package_root/usr/lib/Actium Node Manager/supervisor/install-supervisor-debian.sh"
test -x "$real_binary"
test -f "$real_installer"
build_info="$("$real_binary" --build-info)"
printf '%s\n' "$build_info" | grep -Fq '"product":"actium-node-supervisor"'
"$real_binary" --self-test >/dev/null

cp -- "$installer" "$source_root/install-supervisor-debian.sh"
cp -- "$package_root/usr/lib/Actium Node Manager/supervisor/actium-node-supervisor.service" "$source_root/actium-node-supervisor.service"
cp -- "$package_root/usr/lib/Actium Node Manager/supervisor/actium-node-supervisor-lab.service" "$source_root/actium-node-supervisor-lab.service"
for template in supervisor.toml supervisor.lab.toml; do
  sed \
    -e "s|\"/usr/lib/actium|\"$stage_root/usr/lib/actium|g" \
    -e "s|\"/var/lib/actium|\"$stage_root/var/lib/actium|g" \
    -e "s|\"/var/log/actium|\"$stage_root/var/log/actium|g" \
    -e "s|\"/etc/actium|\"$stage_root/etc/actium|g" \
    -e "s|\"/run/actium|\"$stage_root/run/actium|g" \
    -e "s|\"/actium-lab|\"$stage_root/actium-lab|g" \
    -e "s|\"/actium|\"$stage_root/actium|g" \
    "$package_root/usr/lib/Actium Node Manager/supervisor/$template" > "$source_root/$template"
done
chmod 0755 "$source_root/install-supervisor-debian.sh"

write_stub() {
  target="$1"
  shift
  printf '%s\n' "$@" > "$target"
  chmod 0755 "$target"
}

write_stub "$stub_dir/systemctl" \
  '#!/bin/sh' \
  'printf "%s\n" "systemctl $*" >> "$ACTIUM_SYSTEMCTL_LOG"' \
  'case "$1" in' \
  '  is-active) exit 1 ;;' \
  '  restart) [ "$ACTIUM_FAIL_RESTART" = 1 ] && exit 1; exit 0 ;;' \
  '  *) exit 0 ;;' \
  'esac'
write_stub "$stub_dir/docker" \
  '#!/bin/sh' \
  'if [ "$1" = compose ] && [ "$2" = version ]; then exit 0; fi' \
  'exit 0'
export PATH="$stub_dir:$PATH"
export ACTIUM_SYSTEMCTL_LOG="$work_root/systemctl calls.log"
export ACTIUM_FAIL_RESTART=0

custom_installer="$source_root/install-supervisor-debian.sh"
target_binary="$stage_root/usr/lib/actium/node-manager/actium-node-supervisor"
build_identity_path="$stage_root/var/lib/actium/node-manager/build-identity.json"

DESTDIR="$stage_root" "$custom_installer" --install --channel stable --no-start --binary "$real_binary" >/dev/null
test -f "$target_binary"
test -f "$stage_root/etc/systemd/system/actium-node-supervisor.service"
test -f "$build_identity_path"
grep -Fq '"product":"actium-node-supervisor"' "$build_identity_path"
grep -Fq 'daemon-reload' "$ACTIUM_SYSTEMCTL_LOG"
initial_digest="$(sha256sum "$target_binary" | awk '{print $1}')"

write_fake_supervisor() {
  target="$1"
  check_status="$2"
  build_tag="$3"
  printf '%s\n' \
    '#!/bin/sh' \
    'case "$1" in' \
    '  --self-test) exit 0 ;;' \
    "  --build-info) printf '%s\n' '{\"product\":\"actium-node-supervisor\",\"version\":\"0.5.21\",\"build_id\":\"$build_tag\"}' ;;" \
    'esac' \
    'for argument in "$@"; do' \
    "  [ \"\$argument\" = --check ] && exit $check_status" \
    '  [ "$argument" = --ping ] && exit 0' \
    'done' \
    'exit 0' > "$target"
  chmod 0755 "$target"
}

half_configured_binary="$work_root/half-configured supervisor binary"
write_fake_supervisor "$half_configured_binary" 1 "half-configured"
if DESTDIR="$stage_root" "$custom_installer" --install --channel stable --no-start --binary "$half_configured_binary" >/dev/null 2>&1; then
  echo "rollback de half-configured no fallo" >&2
  exit 1
fi
test "$(sha256sum "$target_binary" | awk '{print $1}')" = "$initial_digest"
test ! -f "$target_binary.next"

health_failure_binary="$work_root/health failure supervisor binary"
write_fake_supervisor "$health_failure_binary" 0 "health-failure"
if ACTIUM_FAIL_RESTART=1 DESTDIR="$stage_root" "$custom_installer" --install --channel stable --binary "$health_failure_binary" >/dev/null 2>&1; then
  echo "rollback por health/systemd no fallo" >&2
  exit 1
fi
test "$(sha256sum "$target_binary" | awk '{print $1}')" = "$initial_digest"
grep -Fq 'systemctl restart actium-node-supervisor.service' "$ACTIUM_SYSTEMCTL_LOG"

DESTDIR="$stage_root" "$custom_installer" --install --channel stable --no-start --binary "$real_binary" >/dev/null
test "$(sha256sum "$target_binary" | awk '{print $1}')" = "$initial_digest"
grep -Fq '"product":"actium-node-supervisor"' "$build_identity_path"
printf '%s\n' 'space-path integration: PASS'
`;

    const args =
      process.platform === "win32"
        ? ["-d", distro, "--user", "root", "--", "bash", "-s", "--", installerWsl, debWsl]
        : ["bash", "-s", "--", installerWsl, debWsl];
    const command = process.platform === "win32" ? "wsl" : "bash";
    const result = spawnSync(command, args, {
      encoding: "utf8",
      input: script,
      maxBuffer: 2 * 1024 * 1024,
    });
    assert.equal(result.error, undefined, command + " no pudo ejecutarse: " + (result.error?.message ?? "error desconocido"));
    assert.equal(result.status, 0, "integración de paths con espacios falló:\n" + result.stdout + "\n" + result.stderr);
    assert.match(result.stdout, /space-path integration: PASS/);
  },
);

console.log("m5-2-space-paths: quoting POSIX, build-info, staging y rollback verificados");
