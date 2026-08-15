import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const installerRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dataPlaneRoot = resolve(installerRoot, '..');
const read = (path) => readFile(resolve(dataPlaneRoot, path), 'utf8');

test('separa liveness bootstrap de readiness steady-state', async () => {
  const [siteCore, manager, runtime] = await Promise.all([
    read('compose.site-core.yml'),
    read('manage-node.sh'),
    read('installer/src-tauri/actium-node-core/src/runtime.rs'),
  ]);
  assert.match(siteCore, /health\/ready/);
  assert.doesNotMatch(siteCore, /healthcheck:[\s\S]{0,300}health\/live/);
  assert.match(manager, /bootstrap-start/);
  assert.match(manager, /bootstrap-start\)[\s\S]*docker "\$@" up -d/);
  assert.doesNotMatch(manager.match(/bootstrap-start\)[\s\S]*?;;/)?.[0] ?? '', /--wait/);
  assert.match(runtime, /wait_site_core_probe\(unit, "\/health\/live", "SITE_CORE_LIVENESS_TIMEOUT"\)/);
  assert.match(runtime, /wait_site_core_probe\(unit, "\/health\/ready", "SITE_CORE_READINESS_TIMEOUT"\)/);
});

test('commissioning usa topologia por cohortes y lifecycle operativo', async () => {
  const [topology, runtime, lifecycle, agent] = await Promise.all([
    read('installer/src-tauri/actium-node-core/src/topology.rs'),
    read('installer/src-tauri/actium-node-core/src/runtime.rs'),
    read('services/agent/src/lifecycle.ts'),
    read('services/agent/src/main.ts'),
  ]);
  assert.match(topology, /RUNTIME_TOPOLOGY_SCHEMA: u8 = 3/);
  assert.match(topology, /startup_cohort/);
  assert.match(topology, /startup_gate/);
  for (const code of [
    'AGENT_ENROLLMENT_TIMEOUT',
    'AGENT_HOST_RECONCILIATION_TIMEOUT',
    'SITE_RUNTIME_SYNC_TIMEOUT',
    'SITE_CORE_READINESS_TIMEOUT',
    'AGENT_REPORTING_TIMEOUT',
  ]) assert.match(runtime, new RegExp(code));
  for (const state of ['starting', 'enrolled', 'host_reconciled', 'runtime_sync_pending', 'runtime_synced', 'site_core_ready', 'reporting', 'degraded']) {
    assert.match(lifecycle, new RegExp(`'${state}'`));
  }
  assert.doesNotMatch(lifecycle, /agent credential|enrollment token|private key/i);
  assert.match(agent, /const acknowledgement = asRecord\(republish\.body\)/);
  assert.match(agent, /siteCoreOperational = !ACTIVE_PROFILES\.has\('site-core'\) \|\| Boolean\(lifecycle\.snapshot\(\)\.siteCoreReadyAt\)/);
  assert.match(agent, /deploymentId: RUNTIME_TOPOLOGY\.deploymentId/);
  assert.match(agent, /runtimeUnitId: RUNTIME_UNIT_ID/);
  assert.match(agent, /await bindManagedNodeHost\(state\.hostId\)[\s\S]*transition\('host_reconciled'/);
});

test('un candidato cold fallido no permanece active', async () => {
  const releases = await read('installer/src-tauri/actium-node-core/src/releases.rs');
  assert.match(releases, /last_failed_release = state\.active_release\.take\(\)/);
  assert.match(releases, /promotion_status = "failed"/);
});
