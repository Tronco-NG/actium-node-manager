import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8").replaceAll("\r\n", "\n");
const wrapper = read("src-tauri/supervisor/install-supervisor-debian.sh");
const preinst = read("src-tauri/supervisor/preinst-debian.sh");
const postinst = read("src-tauri/supervisor/postinst-debian.sh");
const stage = read("scripts/build-supervisor-linux.sh");
const supervisor = read("src-tauri/actium-node-supervisor/src/deployment.rs");
const stableUnit = read("src-tauri/supervisor/actium-node-supervisor.service");
const labUnit = read("src-tauri/supervisor/actium-node-supervisor-lab.service");
const authorityUnit = read("deploy/authority-service/actium-authority.service");
const recoveryUnit = read("src-tauri/supervisor/actium-node-deployment-reconcile.service");
const stableDeploymentDropIn = read("src-tauri/supervisor/zz-actium-node-supervisor-deployment.conf");
const labDeploymentDropIn = read("src-tauri/supervisor/zz-actium-node-supervisor-lab-deployment.conf");
const authorityDeploymentDropIn = read("src-tauri/supervisor/zz-actium-authority-deployment.conf");

test("el wrapper Bash sólo reenvía argv al engine Rust y conserva paths con espacios", () => {
  assert.match(wrapper, /exec "\$binary" deployment "\$@"/);
  assert.match(wrapper, /ACTIUM_NODE_SUPERVISOR_BINARY/);
  assert.doesNotMatch(wrapper, /sed|grep|trust_store_path|systemctl|dpkg|mv --|cp -a/);
  assert.match(stage, /install -m 0755 "\$tauri_root\/target\/release\/actium-node-supervisor"/);
});

test("postinst sólo prepara assets y registra unidades; no activa ni reinicia canales", () => {
  assert.match(postinst, /systemctl daemon-reload/);
  assert.match(postinst, /compatibility-manifest\.json/);
  assert.match(postinst, /STABLE_CONFIG=\$\(rooted \/etc\/actium\/node-manager\)/);
  assert.match(postinst, /LAB_CONFIG=\$\(rooted \/etc\/actium\/node-manager-lab\)/);
  assert.match(postinst, /if \[ ! -e "\$STABLE_CONFIG\/supervisor\.toml" \]/);
  assert.match(postinst, /if \[ ! -e "\$LAB_CONFIG\/supervisor\.toml" \]/);
  assert.match(postinst, /systemctl enable actium-node-deployment-reconcile\.service/);
  assert.match(postinst, /systemctl enable actium-authority\.service/);
  assert.match(postinst, /zz-actium-node-supervisor-deployment\.conf/);
  assert.match(postinst, /zz-actium-node-supervisor-lab-deployment\.conf/);
  assert.match(postinst, /zz-actium-authority-deployment\.conf/);
  assert.match(stableDeploymentDropIn, /service-launch --environment stable/);
  assert.match(labDeploymentDropIn, /service-launch --environment lab/);
  assert.match(authorityDeploymentDropIn, /service-launch --role authority/);
  assert.match(authorityUnit, /service-launch --role authority/);
  assert.match(supervisor, /fn select_supervisor_runtime/);
  assert.match(supervisor, /fn select_preserved_supervisor_binary/);
  assert.match(supervisor, /fn select_authority_runtime/);
  assert.match(supervisor, /legacy\/actium-authority-service/);
  assert.match(supervisor, /authority-package\/actium-authority-service/);
  assert.match(preinst, /authority-runtime\/legacy/);
  assert.match(preinst, /preserve_supervisor_baseline stable/);
  assert.match(preinst, /preserve_supervisor_baseline lab/);
  assert.match(supervisor, /legacy\/actium-node-supervisor/);
  assert.match(preinst, /preservó el runtime Authority legacy sin activarlo/);
  assert.doesNotMatch(preinst, /systemctl (?:start|restart|stop)|docker|deployment (?:stage|activate)/);
  assert.match(postinst, /AUTHORITY_RUNTIME=\$\(rooted \/var\/lib\/actium\/authority-runtime\)/);
  assert.match(supervisor, /authority-package\/actium-authority-service/);
  assert.doesNotMatch(postinst, /systemctl (?:start|restart|stop)|systemctl enable actium-node-supervisor|docker info|docker compose|deployment (?:stage|activate)|--preflight|--install/);
  assert.doesNotMatch(postinst, /TRUST_STORE|trust_store_path|center-local\.token|chmod 0440|migrate_legacy/);
});

test("postinst configura el paquete en un DESTDIR aislado, preserva estado y no activa canales", (t) => {
  if (process.platform !== "win32") {
    t.skip("La prueba de integración utiliza el WSL Debian de Windows.");
    return;
  }

  const wslProbe = spawnSync("wsl.exe", ["-d", "Debian", "--exec", "/bin/true"], { encoding: "utf8" });
  if (wslProbe.error || wslProbe.status !== 0) {
    t.skip("WSL Debian no está disponible en este equipo.");
    return;
  }

  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "actium-postinst-")).replaceAll("\\", "/");
  const linuxPath = (value) => {
    const normalized = value.replaceAll("\\", "/");
    const match = normalized.match(/^([A-Za-z]):\/(.*)$/);
    assert.ok(match, `No se pudo convertir ruta Windows a WSL: ${value}`);
    return `/mnt/${match[1].toLowerCase()}/${match[2]}`;
  };
  const rootFs = path.join(fixture, "rootfs");
  const fakeBin = path.join(fixture, "fakebin");
  const systemctlLog = path.join(fixture, "systemctl.log");
  const supervisorAssets = path.join(rootFs, "usr", "lib", "Actium Node Manager", "supervisor");
  const authorityAssets = path.join(rootFs, "usr", "lib", "Actium Node Manager", "authority-package");
  const oldAuthority = path.join(rootFs, "usr", "lib", "Actium Node Manager", "authority", "actium-authority-service");
  const stableConfig = path.join(rootFs, "etc", "actium", "node-manager", "supervisor.toml");
  const labConfig = path.join(rootFs, "etc", "actium", "node-manager-lab", "supervisor.toml");
  const durableFiles = [
    ["var/lib/actium/authority/authority-state.json", "preserve-authority-state\n"],
    ["var/lib/actium/authority/trust-bundle.json", "preserve-authority-trust-bundle\n"],
    ["var/lib/actium/authority/authority-lifecycle.json", "preserve-authority-lifecycle\n"],
    ["etc/actium/authority/sealing.key", "preserve-sealing-material\n"],
    ["etc/actium/authority/center-local.token", "preserve-center-token\n"],
    ["var/lib/actium/node-manager/trust/trust-bundle.json", "preserve-stable-trust-store\n"],
    ["var/lib/actium/node-manager-lab/trust/trust-bundle.json", "preserve-lab-trust-store\n"],
    ["var/lib/actium/node-manager/identity/host-identity.json", "preserve-host-identity\n"],
    ["var/lib/actium/node-manager/host-installation-id", "preserve-installation-id\n"],
    ["var/lib/actium/node-manager/storage-grants/grants.json", "preserve-storage-grants\n"],
    ["var/lib/actium/node-manager/extensions/registry.json", "preserve-extension-registry\n"],
    ["actium/registry.json", "preserve-node-registry\n"],
    ["actium/nodes/historical-node/.actium-node-installation.json", "preserve-node-installation\n"],
  ].map(([relative, contents]) => [path.join(rootFs, ...relative.split("/")), contents]);
  const sourceSupervisor = path.join(root, "src-tauri", "supervisor");
  const supervisorNames = [
    "actium-node-supervisor", "actium-node-supervisor.service", "actium-node-supervisor-lab.service",
    "actium-node-deployment-reconcile.service", "zz-actium-node-supervisor-deployment.conf",
    "zz-actium-node-supervisor-lab-deployment.conf", "zz-actium-authority-deployment.conf",
    "supervisor.toml", "supervisor.lab.toml", "compatibility-manifest.json",
  ];
  const authorityNames = [
    "actium-authority-service", "actium-authority-ceremony", "actium-authority-rebuild-trust-bundle",
    "actium-authority.service",
  ];
  const scripts = {
    id: "#!/bin/sh\nprintf '0\\n'\n",
    dpkg: "#!/bin/sh\nprintf 'amd64\\n'\n",
    getent: "#!/bin/sh\nexit 2\n",
    groupadd: "#!/bin/sh\nexit 0\n",
    useradd: "#!/bin/sh\nexit 0\n",
    chmod: "#!/bin/sh\nexit 0\n",
    chown: "#!/bin/sh\nexit 0\n",
    systemctl: "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$POSTINST_SYSTEMCTL_LOG\"\n",
    install: "#!/bin/bash\nargs=()\nwhile (( $# )); do\n  case \"$1\" in\n    -o|-g) shift 2 ;;\n    *) args+=(\"$1\"); shift ;;\n  esac\ndone\nexec /usr/bin/install \"${args[@]}\"\n",
  };

  try {
    fs.mkdirSync(path.join(rootFs, "etc"), { recursive: true });
    fs.writeFileSync(path.join(rootFs, "etc", "os-release"), "ID=debian\n");
    fs.mkdirSync(supervisorAssets, { recursive: true });
    fs.mkdirSync(authorityAssets, { recursive: true });
    fs.mkdirSync(fakeBin, { recursive: true });
    fs.mkdirSync(path.dirname(oldAuthority), { recursive: true });
    fs.writeFileSync(oldAuthority, "previous-serving-authority-binary");
    for (const name of supervisorNames) {
      const source = path.join(sourceSupervisor, name);
      const destination = path.join(supervisorAssets, name);
      if (fs.existsSync(source)) fs.copyFileSync(source, destination);
      else fs.writeFileSync(destination, `fixture executable: ${name}\n`);
    }
    for (const name of authorityNames) {
      const source = path.join(root, "deploy", "authority-service", name);
      const destination = path.join(authorityAssets, name);
      if (fs.existsSync(source)) fs.copyFileSync(source, destination);
      else fs.writeFileSync(destination, `fixture executable: ${name}\n`);
    }
    fs.mkdirSync(path.dirname(stableConfig), { recursive: true });
    fs.writeFileSync(stableConfig, "operator_stable_config = true\n");
    for (const [file, contents] of durableFiles) {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, contents);
    }
    for (const [name, content] of Object.entries(scripts)) {
      fs.writeFileSync(path.join(fakeBin, name), content);
    }

    const linuxFakeBin = linuxPath(fakeBin);
    const chmod = spawnSync("wsl.exe", ["-d", "Debian", "--exec", "/bin/chmod", "+x", ...Object.keys(scripts).map((name) => `${linuxFakeBin}/${name}`)], { encoding: "utf8" });
    assert.equal(chmod.status, 0, chmod.stderr || chmod.error?.message);

    const preinstPath = linuxPath(path.join(root, "src-tauri", "supervisor", "preinst-debian.sh"));
    const postinstPath = linuxPath(path.join(root, "src-tauri", "supervisor", "postinst-debian.sh"));
    const rootFsPath = linuxPath(rootFs);
    const logPath = linuxPath(systemctlLog);
    const run = () => spawnSync("wsl.exe", [
      "-d", "Debian", "--exec", "/usr/bin/env",
      `DESTDIR=${rootFsPath}`,
      `PATH=${linuxFakeBin}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`,
      `POSTINST_SYSTEMCTL_LOG=${logPath}`,
      "/bin/sh", postinstPath,
    ], { encoding: "utf8" });

    const preinstRun = spawnSync("wsl.exe", [
      "-d", "Debian", "--exec", "/usr/bin/env",
      `DESTDIR=${rootFsPath}`,
      `PATH=${linuxFakeBin}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`,
      "/bin/sh", preinstPath,
    ], { encoding: "utf8" });
    assert.equal(preinstRun.status, 0, `${preinstRun.stdout}\n${preinstRun.stderr}`);
    const preservedAuthority = path.join(rootFs, "var", "lib", "actium", "authority-runtime", "legacy", "actium-authority-service");
    assert.equal(fs.readFileSync(preservedAuthority, "utf8"), "previous-serving-authority-binary");
    for (const stateRoot of ["node-manager", "node-manager-lab"]) {
      const preservedSupervisor = path.join(rootFs, "var", "lib", "actium", stateRoot, "legacy", "actium-node-supervisor");
      assert.equal(fs.readFileSync(preservedSupervisor, "utf8"), "fixture executable: actium-node-supervisor\n");
    }
    const repeatedPreinst = spawnSync("wsl.exe", [
      "-d", "Debian", "--exec", "/usr/bin/env",
      `DESTDIR=${rootFsPath}`,
      `PATH=${linuxFakeBin}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`,
      "/bin/sh", preinstPath,
    ], { encoding: "utf8" });
    assert.equal(repeatedPreinst.status, 0, `${repeatedPreinst.stdout}\n${repeatedPreinst.stderr}`);

    const firstRun = run();
    assert.equal(firstRun.status, 0, `${firstRun.stdout}\n${firstRun.stderr}`);
    assert.equal(fs.readFileSync(stableConfig, "utf8"), "operator_stable_config = true\n");
    assert.equal(fs.readFileSync(labConfig, "utf8"), fs.readFileSync(path.join(supervisorAssets, "supervisor.lab.toml"), "utf8"));
    for (const [file, contents] of durableFiles) {
      assert.equal(fs.readFileSync(file, "utf8"), contents, `postinst alteró estado durable: ${file}`);
    }
    assert.ok(fs.existsSync(path.join(rootFs, "var", "lib", "actium", "authority-runtime", "deployments")));
    for (const name of [
      "actium-node-supervisor.service", "actium-node-supervisor-lab.service",
      "actium-node-deployment-reconcile.service", "actium-authority.service",
    ]) assert.ok(fs.existsSync(path.join(rootFs, "lib", "systemd", "system", name)), `unit no instalada: ${name}`);
    assert.ok(fs.existsSync(path.join(rootFs, "lib", "systemd", "system", "actium-node-supervisor.service.d", "zz-actium-deployment-runtime.conf")));
    assert.ok(fs.existsSync(path.join(rootFs, "lib", "systemd", "system", "actium-node-supervisor-lab.service.d", "zz-actium-deployment-runtime.conf")));
    assert.ok(fs.existsSync(path.join(rootFs, "lib", "systemd", "system", "actium-authority.service.d", "zz-actium-deployment-runtime.conf")));
    assert.deepEqual(fs.readFileSync(systemctlLog, "utf8").trim().split("\n"), [
      "daemon-reload", "enable actium-authority.service", "enable actium-node-deployment-reconcile.service",
    ]);

    const secondRun = run();
    assert.equal(secondRun.status, 0, `${secondRun.stdout}\n${secondRun.stderr}`);
    assert.equal(fs.readFileSync(stableConfig, "utf8"), "operator_stable_config = true\n");
    assert.equal(fs.readFileSync(labConfig, "utf8"), fs.readFileSync(path.join(supervisorAssets, "supervisor.lab.toml"), "utf8"));
    for (const [file, contents] of durableFiles) {
      assert.equal(fs.readFileSync(file, "utf8"), contents, `repetir postinst alteró estado durable: ${file}`);
    }
    const calls = fs.readFileSync(systemctlLog, "utf8").trim().split("\n");
    assert.equal(calls.filter((call) => call === "daemon-reload").length, 2);
    assert.equal(calls.filter((call) => call === "enable actium-node-deployment-reconcile.service").length, 2);
    assert.equal(calls.filter((call) => call === "enable actium-authority.service").length, 2);
    assert.ok(calls.every((call) => !/\b(start|restart|stop)\b|actium-node-supervisor(?:-lab)?\.service|docker/.test(call)));
  } finally {
    fs.rmSync(fixture, { recursive: true, force: true });
  }
});

test("las unidades ejecutan el deployment versionado sin rutas legacy", () => {
  assert.match(stableUnit, /service-launch --environment stable/);
  assert.match(labUnit, /service-launch --environment lab/);
  assert.match(authorityUnit, /service-launch --role authority/);
  assert.match(authorityUnit, /ReadOnlyPaths=\/var\/lib\/actium\/authority-runtime/);
  assert.match(recoveryUnit, /deployment reconcile-all/);
  assert.match(recoveryUnit, /After=.*actium-node-supervisor-lab\.service/);
  assert.match(fs.readFileSync(path.join(root, "src-tauri/tauri.conf.json"), "utf8"), /resources\/authority\/": "authority-package\//);
  assert.match(fs.readFileSync(path.join(root, "src-tauri/tauri.conf.json"), "utf8"), /preInstallScript": "supervisor\/preinst-debian\.sh/);
  assert.doesNotMatch(stableDeploymentDropIn + labDeploymentDropIn, /current\/runtime\/actium-node-supervisor/);
});

test("el engine mantiene staging, preflight, activación atómica, rollback y recovery", () => {
  for (const contract of [
    "READY_TO_ACTIVATE", "PreflightPassed", "Activating", "Verifying", "Committed",
    "RollingBack", "RolledBack", "rollback-receipt.json", "atomic_symlink_switch",
    "restore_trust_store_snapshot", "reconcile_deployment", "reconcile_pending_transactions", "lab_receipt_digest",
  ]) assert.ok(supervisor.includes(contract), `deployment contract ausente: ${contract}`);
  assert.match(supervisor, /current deployment changed after stage/);
  assert.match(supervisor, /Trust Store restore/);
  assert.match(supervisor, /SERVED_READY/);
  assert.match(supervisor, /capture-authority-baseline/);
  assert.match(supervisor, /perform_initial_install_rollback/);
  assert.match(supervisor, /ROLLED_BACK_NO_ACTIVE_SUPERVISOR/);
  assert.match(supervisor, /first_activation_recovery_accepts_only_absent_or_candidate_pointer/);
});

console.log("m5-2-space-paths: POSIX wrapper, package separation and versioned runtime paths verified");
