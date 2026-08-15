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
  assert.match(runtime, /"radio-saf" => vec!\["objects", "radio-archive"\]/);
  assert.doesNotMatch(runtime, /"radio-saf" => vec!\["minio", "radio-archive"\]/);
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
  assert.match(runtime, /recover_after_reboot[\s\S]{0,800}recover_interrupted\(\)/);
  assert.doesNotMatch(releases, /fn write_json_atomic[\s\S]{0,500}remove_file\(path\)/);
});
