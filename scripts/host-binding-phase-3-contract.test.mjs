import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const read = (relative) => readFile(join(root, relative), 'utf8');
const manager = await read('src-tauri/src/lib.rs');
const ipc = await read('src-tauri/actium-node-core/src/ipc.rs');
const supervisor = await read('src-tauri/actium-node-supervisor/src/main.rs');

for (const field of ['binding_id', 'nonce', 'client_id', 'organization_id', 'site_id', 'host_id', 'host_installation_id', 'deployment_id', 'allowed_capabilities', 'deployment_channel', 'binding_epoch', 'policy_hash', 'issued_at', 'expires_at']) {
  assert.match(manager, new RegExp(`${field}:`), `falta validación de ${field}`);
}
assert.match(manager, /host_binding: Option<HostBindingClaims>/);
assert.match(manager, /validate_host_binding_claims\(&claims\)/);
assert.match(manager, /SupervisorCommand::HostIdentity/);
assert.match(manager, /el \.adpe pertenece a otra instalación de Host/);
assert.match(manager, /ENROLLMENT_REQUIRED:.*identidad de Host/);
assert.match(manager, /ACTIUM_HOST_BINDING_EPOCH=/);
assert.match(ipc, /HostIdentity as HostIdentityRecord/);
assert.match(ipc, /HostIdentity \{ identity: Option<HostIdentityRecord> \}/);
assert.match(supervisor, /SupervisorCommand::HostIdentity => Ok\(SupervisorReply::HostIdentity/);
assert.doesNotMatch(manager, /deployment_id:\s*""/);

console.log('host-binding-phase-3-contract: ok');
