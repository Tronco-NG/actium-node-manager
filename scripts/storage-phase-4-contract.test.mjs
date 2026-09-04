import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const read = (relative) => readFile(join(root, relative), 'utf8');
const core = await read('src-tauri/actium-node-core/src/storage_grant.rs');
const supervisor = await read('src-tauri/actium-node-supervisor/src/main.rs');

assert.match(core, /pub fn discovery_snapshot_hash\(mounts: &\[StorageMount\]\)/);
assert.match(core, /pub report_generation: u64/);
assert.match(core, /pub snapshot_hash: String/);
assert.match(core, /option\.trim\(\) == "ro"/);
assert.match(core, /NON_GRANTABLE_FILESYSTEMS/);
assert.match(core, /visit\(child, observed, candidates\)/);
assert.match(core, /findmnt_walks_children_and_keeps_external_identity/);
assert.match(core, /errors=remount-ro/);

assert.match(supervisor, /let snapshot_hash=discovery_snapshot_hash\(&mounts\)/);
assert.match(supervisor, /format!\("storage:\{\}:\{\}:\{\}"/);
assert.match(supervisor, /STORAGE_GRANT_IDEMPOTENCY_REPLAY/);
assert.match(supervisor, /report_generation:mount\.report_generation/);
assert.match(supervisor, /snapshot_hash/);
assert.match(supervisor, /STORAGE_FILESYSTEM_READONLY/);
assert.match(supervisor, /STORAGE_GRANT_SITE_MISMATCH/);
assert.match(supervisor, /m\.filesystem_uuid\.as_deref\(\)==Some\(g\.filesystem_uuid\.as_str\(\)\)/);

console.log('storage-phase-4: ok');
