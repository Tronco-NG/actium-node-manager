import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const source = await readFile(join(root, 'src/main.ts'), 'utf8');

// Gate 1.5 keeps Node Manager useful offline while refusing to fabricate a
// Center approval.  These assertions protect the cross-repo boundary until
// the signed Manager → Center transport is implemented in Fases 3–5.
assert.match(source, /function storageScopeRequest\(\)/);
assert.match(source, /deploymentId:\s*bootstrapValidation\?\.deploymentId\s*\?\?\s*installation\.deploymentId/);
assert.match(source, /hostId:\s*bootstrapValidation\?\.hostId\s*\?\?\s*config\.ACTIUM_HOST_ID/);
assert.match(source, /hostInstallationId:\s*bootstrapValidation\?\.hostInstallationId\s*\?\?\s*installation\.hostInstallationId/);
assert.match(source, /if \(!scope\.deploymentId \|\| !scope\.organizationId \|\| !scope\.siteId \|\| !scope\.hostId \|\| !scope\.hostInstallationId\)/);
assert.match(source, /draft\.phase = "enrollment_required"/);
assert.match(source, /storageCapabilitiesForProfiles\(\)\.map\(\(capability\)/);
assert.match(source, /data-storage-capability/);
assert.match(source, /storage-grant-preflight/);
assert.match(source, /La reubicación rápida está deshabilitada/);
assert.doesNotMatch(source, /approved_by\s*:/);
assert.doesNotMatch(source, /service_role/);

console.log('storage-gate-1.5-contract: ok');
