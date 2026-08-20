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
  assert.match(
    agent,
    /siteCoreOperational = !ACTIVE_PROFILES\.has\('site-core'\)\s*\|\| SITE_CORE_CANDIDATE\s*\|\| Boolean\(lifecycle\.snapshot\(\)\.siteCoreReadyAt\)/,
  );
  assert.match(agent, /if \(!SITE_CORE_CANDIDATE && !lifecycle\.snapshot\(\)\.siteCoreReadyAt\)/);
  assert.match(agent, /registration\.authority_routable !== false/);
  assert.match(agent, /registration\.activation_supported !== false/);
  assert.match(agent, /registration\.blocker !== 'physical_fence_receipt_required'/);
  assert.match(agent, /deploymentId: RUNTIME_TOPOLOGY\.deploymentId/);
  assert.match(agent, /runtimeUnitId: RUNTIME_UNIT_ID/);
  assert.match(agent, /await bindManagedNodeHost\(state\.hostId\)[\s\S]*transition\('host_reconciled'/);
});

test('issuer .adpe firma solo workloads enabled no-base y Site Core puro es site-core', async () => {
  const issuer = await readFile(
    resolve(installerRoot, '..', '..', '..', '..', 'actium-center', 'supabase', 'functions', 'actium-data-plane-bootstrap', 'index.ts'),
    'utf8',
  ).catch(() => '');
  const rust = await read('installer/src-tauri/actium-node-core/src/capability_surface.rs');
  assert.match(rust, /installer_min_version_for_profiles/);
  assert.match(rust, /"0\.3\.0"/);
  assert.match(rust, /"0\.4\.0"/);
  if (issuer) {
    assert.match(issuer, /desired_status === 'enabled' && workload.profile && workload.profile !== 'base'/);
    assert.match(issuer, /installer_min_version: '0.3.0'/);
    assert.match(issuer, /connectivity_installer_min_version: '0.4.0'/);
    assert.match(issuer, /hasConnectivity/);
  }
});

test('un candidato cold fallido no permanece active', async () => {
  const releases = await read('installer/src-tauri/actium-node-core/src/releases.rs');
  assert.match(releases, /let failed = state[\s\S]*active_release[\s\S]*\.take\(\)/);
  assert.match(releases, /state\.last_failed_release = Some\(failed\.clone\(\)\)/);
  assert.match(releases, /impl Drop for ReleasePromotion/);
  assert.match(releases, /promotion_status = "failed"/);
  assert.match(releases, /promotion_status = "recovery_pending"/);
});
