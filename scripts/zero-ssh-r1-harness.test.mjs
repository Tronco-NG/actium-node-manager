import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

test('Zero-SSH R1 operations are typed and SSH is not in the product path', () => {
  const remoteOps = readFileSync(join(root, 'src-tauri/actium-node-core/src/remote_ops.rs'), 'utf8');
  for (const op of [
    'RestartConnector',
    'RepairConnectivity',
    'ApplyConnectivityPolicy',
    'TriggerDiagnostics',
  ]) {
    assert.match(remoteOps, new RegExp(op));
  }
  assert.match(remoteOps, /HostManagementRequestV1/);
  assert.match(remoteOps, /PollJobs/);
  assert.match(remoteOps, /ClaimJob/);
  assert.match(remoteOps, /SubmitReceipt/);
  assert.match(remoteOps, /HOST_MANAGEMENT_AUTH_REQUIRED/);
  assert.doesNotMatch(remoteOps, /ssh -i/);
  assert.doesNotMatch(remoteOps, /std::process::Command::new\("ssh"\)/);
});
