import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const read = (path) => readFile(new URL(path, import.meta.url), 'utf8');

test('separa estado Agent writable de evidencia Supervisor read-only', async () => {
  const compose = await read('../../compose.agent.yml');
  assert.match(compose, /\/state\/agent:\/var\/lib\/actium-node-config"/);
  assert.match(compose, /\/state\/supervisor:\/var\/lib\/actium-supervisor-evidence:ro"/);
  assert.match(compose, /ACTIUM_MATERIAL_ATTESTATION_PATH: \/var\/lib\/actium-supervisor-evidence\/material-attestation\.json/);
  assert.doesNotMatch(compose, /state\/node-runtime:\/var\/lib\/actium-node-config/);
});

test('Site Core materializa secrets 0400 fuera del volumen durable', async () => {
  const [compose, entrypoint] = await Promise.all([
    read('../../compose.site-core.yml'),
    read('../../services/site-core/docker-entrypoint.sh'),
  ]);
  assert.match(compose, /\/run\/actium-site-core-secrets:rw,noexec,nosuid,nodev,mode=0710/);
  assert.match(entrypoint, /install -o node -g node -m 0400/);
  assert.match(entrypoint, /runtime_secrets_dir\/postgres-password/);
  assert.doesNotMatch(entrypoint, /"\$data_dir\/\.secrets\/postgres-password"/);
});

test('Radio S&F usa el mismo storage objects que prepara Supervisor', async () => {
  const [compose, runtime] = await Promise.all([
    read('../../compose.radio-saf.yml'),
    read('../src-tauri/actium-node-core/src/runtime.rs'),
  ]);
  assert.match(compose, /chroot --userspec=1000:1000 \/ minio server \/data/);
  assert.match(compose, /exec su-exec node:node node dist\/main\.js/);
  assert.match(compose, /\/objects:\/data"/);
  assert.match(runtime, /relative: "objects",\s*mode: 0o750,\s*uid: 1000,\s*gid: 1000/u);
  assert.match(runtime, /relative: "radio-archive",\s*mode: 0o750,\s*uid: 1000,\s*gid: 1000/u);
  assert.doesNotMatch(runtime, /relative: "minio"/u);
});

test('storage de runtime unit recupera ownership antes de ceder el root', async () => {
  const [runtime, unit] = await Promise.all([
    read('../src-tauri/actium-node-core/src/runtime.rs'),
    read('../src-tauri/supervisor/actium-node-supervisor-lab.service'),
  ]);
  assert.match(runtime, /prepare_runtime_unit_storage_root\(&root\)\?[\s\S]*set_runtime_unit_storage_child_owner[\s\S]*finalize_runtime_unit_storage_root\(&root\)/u);
  assert.match(runtime, /relative: "site-core",\s*mode: 0o700,\s*uid: 0,\s*gid: 0/u);
  assert.match(runtime, /reject_unsafe_entries\(&declared\)/);
  assert.match(unit, /^CapabilityBoundingSet=CAP_CHOWN$/mu);
  assert.doesNotMatch(unit, /CAP_DAC_OVERRIDE|CAP_DAC_READ_SEARCH|CAP_FOWNER/u);
});

test('Docker CLI del Supervisor usa config dedicada fuera de root', async () => {
  const [lab, stable, installer] = await Promise.all([
    read('../src-tauri/supervisor/actium-node-supervisor-lab.service'),
    read('../src-tauri/supervisor/actium-node-supervisor.service'),
    read('../src-tauri/supervisor/install-supervisor-debian.sh'),
  ]);

  assert.match(
    lab,
    /^Environment=DOCKER_CONFIG=\/var\/lib\/actium\/node-manager-lab\/docker-cli$/mu,
  );
  assert.match(
    stable,
    /^Environment=DOCKER_CONFIG=\/var\/lib\/actium\/node-manager\/docker-cli$/mu,
  );

  assert.match(lab, /^ProtectHome=true$/mu);
  assert.match(stable, /^ProtectHome=true$/mu);
  assert.match(lab, /^CapabilityBoundingSet=CAP_CHOWN$/mu);
  assert.match(stable, /^CapabilityBoundingSet=CAP_CHOWN$/mu);

  assert.doesNotMatch(
    `${lab}\n${stable}`,
    /CAP_DAC_OVERRIDE|CAP_DAC_READ_SEARCH|CAP_FOWNER/u,
  );

  assert.match(installer, /docker_cli_dir="\$state_dir\/docker-cli"/u);
  assert.match(installer, /docker_cli_config="\$docker_cli_dir\/config\.json"/u);
  assert.match(
    installer,
    /install -d -m 0700 -o root -g root "\$docker_cli_dir"/u,
  );
  assert.match(
    installer,
    /DOCKER_CONFIG="\$docker_cli_dir" docker compose version/u,
  );
  assert.match(installer, /chmod 0600 "\$docker_cli_config"/u);
});

test('storage del Agent recupera root antes de chmod y cede 1000:1000 al final', async () => {
  const [runtime, script] = await Promise.all([
    read('../src-tauri/actium-node-core/src/runtime.rs'),
    read('./run-capchown-storage-test.sh'),
  ]);
  assert.match(runtime, /prepare_agent_storage_root\(&persistent_agent\)\?[\s\S]*finalize_agent_storage_root\(&persistent_agent\)\?[\s\S]*finalize_agent_storage_root\(&agent_state\)/u);
  assert.match(runtime, /fn prepare_agent_storage_root\(/);
  assert.match(runtime, /fn finalize_agent_storage_root\(/);
  assert.match(script, /grep -v '\^cap_chown\$'/u);
  assert.match(script, /sudo capsh --drop="\$drop_caps" --no-new-privs/u);
  assert.match(script, /ACTIUM_ASSERT_CHOWN_ONLY=1/u);
  assert.match(script, /storage_agent_recupera_retry_parcial_sin_dac_ni_fowner/);
});

test('reconciliadores privilegiados no siguen symlinks de workloads', async () => {
  const [runtime, fsBound, script, workflow] = await Promise.all([
    read('../src-tauri/actium-node-core/src/runtime.rs'),
    read('../src-tauri/actium-node-core/src/privileged_fs.rs'),
    read('./run-filesystem-nofollow-test.sh'),
    read('../../../../.github/workflows/actium-telemetry-node-installer.yml'),
  ]);
  assert.match(fsBound, /RESOLVE_NO_SYMLINKS/);
  assert.match(fsBound, /O_NOFOLLOW/);
  assert.match(fsBound, /fstatat/);
  assert.match(fsBound, /fchownat/);
  assert.match(fsBound, /AT_SYMLINK_NOFOLLOW/);
  assert.match(fsBound, /fn fchown\(|fchown\(/);
  assert.match(fsBound, /WORKLOAD_SYMLINK_REJECTED/);
  assert.match(fsBound, /WORKLOAD_SPECIAL_FILE_REJECTED/);
  assert.doesNotMatch(fsBound, /canonicalize\(/);
  assert.match(runtime, /prepare_agent_state_storage_unix/);
  assert.match(runtime, /reject_unsafe_entries/);
  assert.match(script, /storage_agent_rechaza_symlink_y_no_sigue_al_objetivo/);
  assert.match(script, /storage_fabric_nats_recupera_sin_dac/);
  assert.match(workflow, /filesystem-nofollow-boundary/);
  const example = await read('../src-tauri/actium-node-core/examples/verify-cold-commissioning.rs');
  assert.match(example, /nofollow-sentinel/);
  assert.doesNotMatch(example, /host-identity\.json"[\s\S]{0,200}fabric_before/u);
});

test('wizard prefiere LAN host pero conserva el selector manual de interfaces', async () => {
  const manager = await read('../src/main.ts');
  assert.match(manager, /function defaultNetworkAddress\(\): NetworkAddress \| undefined \{[\s\S]{0,1800}docker0[\s\S]{0,1800}\[\.\.\.system\.networkAddresses\]\.sort/u);
  assert.match(manager, /function networkInterfaceOptions\(selected: string\): string \{\s*const interfaces = \[\.\.\.new Set\(system\.networkAddresses\.map/u);
  assert.match(manager, /Sin selección explícita/u);
});

test('el artefacto MSI Lab conserva identidad Lab y version Windows numerica', async () => {
  const tauriLab = JSON.parse(await read('../src-tauri/tauri.lab.conf.json'));
  assert.match(tauriLab.version, /^0\.7\.0-lab\.\d+$/u);
  const lab = String(tauriLab.version).match(/^0\.7\.0-lab\.(\d+)$/u);
  assert.ok(lab, 'Manager Lab debe usar 0.7.0-lab.N');
  assert.equal(tauriLab.bundle.windows.wix.version, `0.7.0.${lab[1]}`);
});

test('resume de commissioning incompleto no debilita el destino vacio inicial', async () => {
  const [core, ipc, manager, ui] = await Promise.all([
    read('../src-tauri/actium-node-core/src/runtime.rs'),
    read('../src-tauri/actium-node-core/src/ipc.rs'),
    read('../src-tauri/src/lib.rs'),
    read('../src/main.ts'),
  ]);
  assert.match(core, /fn prepare_incomplete_commission_root\(/);
  assert.match(core, /prepare_new_node_root\(/);
  assert.match(manager, /resume_incomplete/);
  assert.match(ipc, /IPC_PROTOCOL_VERSION: u16 = 3/);
  assert.match(ipc, /host_identity_v1/);
  assert.match(ipc, /capability_scoped_config/);
  assert.match(manager, /ACTIUM_NODE_INSTALLATION_ID/);
  assert.doesNotMatch(manager, /ACTIUM_HOST_CODE=\{\}/u);
  assert.doesNotMatch(
    manager,
    /and_then\(\|value\| value\.installation_id\.clone\(\)\)\s*\.or_else\(\|\| config\.get\("ACTIUM_HOST_INSTALLATION_ID"\)/u,
  );
  assert.match(manager, /fn incomplete_commission_resume_allowed\(/);
  assert.match(manager, /El commissioning 0.7 solo acepta un destino nuevo y vacio/);
  assert.match(ui, /networkModeHelp\.textContent = networkModeDescription\(networkModeSelect\.value\)/);
  assert.match(ui, /if \(mode === "trusted_lan"\) return "/);
});

test('callers productivos comienzan promociones mediante el guard transaccional', async () => {
  const [core, manager] = await Promise.all([
    read('../src-tauri/actium-node-core/src/runtime.rs'),
    read('../src-tauri/src/lib.rs'),
  ]);
  assert.doesNotMatch(core, /releases\.promote\(/);
  assert.doesNotMatch(manager, /release_manager\.promote\(|releases\.promote\(/);
  assert.match(core, /begin_promotion\(/);
  assert.match(manager, /begin_promotion\(/);
});

test('estado autoritativo usa genesis, heads durables, CAS y locks de filesystem', async () => {
  const [releases, attestation, runtime, durability] = await Promise.all([
    read('../src-tauri/actium-node-core/src/releases.rs'),
    read('../src-tauri/actium-node-core/src/attestation.rs'),
    read('../src-tauri/actium-node-core/src/runtime.rs'),
    read('../src-tauri/actium-node-core/src/durability.rs'),
  ]);
  assert.match(releases, /state\/release-state-v2/);
  assert.match(releases, /try_lock_exclusive/);
  assert.match(releases, /RELEASE_REVISION_CONFLICT/);
  assert.match(releases, /STALE_PROMOTION_OWNER/);
  assert.match(releases, /sync_all\(\)/);
  assert.match(attestation, /material-attestations-v1/);
  assert.match(attestation, /\.lock_exclusive\(\)/);
  assert.match(attestation, /attestation-journal-v1\.initialized\.json/);
  assert.match(attestation, /material-attestation-head-v1\.json/);
  assert.match(attestation, /ATTESTATION_JOURNAL_MISSING/);
  assert.match(attestation, /ATTESTATION_IDENTITY_MISSING/);
  assert.match(durability, /PublishedButDurabilityUnknown/);
  assert.match(durability, /MoveFileExW/);
  assert.match(durability, /MOVEFILE_WRITE_THROUGH/);
  assert.match(runtime, /reconcile_automatic_networks[\s\S]{0,1200}lock_mutation\(\)/);
  assert.match(runtime, /recover_after_reboot[\s\S]{0,800}reconcile_node_runtime\(/);
  assert.match(runtime, /recover_interrupted_locked\(/);
  assert.doesNotMatch(releases, /fn write_json_atomic[\s\S]{0,500}remove_file\(path\)/);
});

test('Manager delega administrabilidad al Supervisor sin inspeccionar la release privilegiada', async () => {
  const manager = await read('../src-tauri/src/lib.rs');

  const block = manager.match(
    /let can_manage = state\.operational[\s\S]{0,600}?;/u,
  );

  assert.ok(block, 'No se encontro el calculo can_manage');

  assert.match(block[0], /supervisor_client\(\)/u);
  assert.match(
    block[0],
    /supervisor_handshake\(&client\)\.compatible/u,
  );

  assert.doesNotMatch(
    block[0],
    /active_runtime_dir|manage-node\.sh|manage-node\.ps1/u,
  );
});
