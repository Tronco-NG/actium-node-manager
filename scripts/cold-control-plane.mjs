import { createHash, createPrivateKey, sign } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:https';

const [configPath] = process.argv.slice(2);
if (!configPath) throw new Error('Uso: cold-control-plane.mjs <config.json>');
const config = JSON.parse(await readFile(configPath, 'utf8'));
const fixture = JSON.parse(await readFile(config.fixturePath, 'utf8'));
const rootPrivateKey = createPrivateKey(await readFile(config.rootPrivateKeyPath, 'utf8'));
const credential = `adpa_${'a'.repeat(96)}`;
let sitePublicJwk = null;
let republished = false;
const packageCache = new Map();

const canonical = (value) => value === null
  ? 'null'
  : Array.isArray(value)
    ? `[${value.map(canonical).join(',')}]`
    : typeof value === 'object'
      ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
      : JSON.stringify(value);
const hashContract = (value) => createHash('sha256').update(canonical(value)).digest('hex');
const decodeContract = (token) => JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8')).contract;
const signContract = (contract, typ, subject) => {
  const protectedHeader = Buffer.from(JSON.stringify({ alg: 'EdDSA', kid: 'cold-control-root', typ })).toString('base64url');
  const now = Math.floor(Date.now() / 1_000);
  const payload = Buffer.from(JSON.stringify({
    contract,
    contract_sha256: hashContract(contract),
    iss: config.expectedIssuer,
    aud: 'actium-site-core',
    sub: subject,
    iat: now - 60,
    exp: 4_102_444_799,
  })).toString('base64url');
  const signature = sign(null, Buffer.from(`${protectedHeader}.${payload}`), rootPrivateKey).toString('base64url');
  return `${protectedHeader}.${payload}.${signature}`;
};

function materializePackage() {
  if (!sitePublicJwk) throw new Error('site_authority_key_not_registered');
  const cacheKey = republished ? 'republished' : 'initial';
  if (packageCache.has(cacheKey)) return packageCache.get(cacheKey);
  const bundle = structuredClone(decodeContract(fixture.package.bundle_jws));
  const delegation = structuredClone(decodeContract(fixture.package.delegation_jws));
  bundle.trust_anchor_id = 'cold-control-root';
  bundle.signature.kid = 'cold-control-root';
  delegation.site_public_key = structuredClone(sitePublicJwk);
  delegation.signature.kid = 'cold-control-root';
  if (republished) {
    bundle.runtime_topology = {
      schema_version: '1.0',
      deployment_id: config.deploymentId,
      host_id: config.hostId,
      source: 'cold-commissioning-control-plane',
    };
    bundle.organization = {
      organization_id: bundle.organization_id,
      display_name: 'Actium Cold Commissioning Fixture',
    };
  }
  const packageValue = {
    ...structuredClone(fixture.package),
    publication_id: republished ? 'ffffffff-ffff-4fff-8fff-ffffffffffff' : fixture.package.publication_id,
    created_at: new Date().toISOString(),
    bundle_jws: signContract(bundle, bundle.signature.typ, 'site:cold:bundle'),
    delegation_jws: signContract(delegation, delegation.signature.typ, 'site:cold:delegation'),
  };
  if (config.invalidPackage) {
    packageValue.bundle_jws = `${packageValue.bundle_jws.slice(0, -1)}${packageValue.bundle_jws.endsWith('A') ? 'B' : 'A'}`;
  }
  packageCache.set(cacheKey, packageValue);
  return packageValue;
}

async function record(event, details = {}) {
  await writeFile(config.eventsPath, `${JSON.stringify({ event, at: new Date().toISOString(), ...details })}\n`, { flag: 'a' });
}

const server = createServer({
  key: await readFile(config.keyPath),
  cert: await readFile(config.certPath),
}, async (request, response) => {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : null;
  const send = (status, value, headers = {}) => {
    response.writeHead(status, { 'content-type': 'application/json', ...headers });
    response.end(`${JSON.stringify(value)}\n`);
  };
  try {
    switch (request.url) {
      case '/enroll':
        await record('enroll');
        return send(200, {
          agent_credential: credential,
          credential_expires_at: '2099-12-31T23:59:59.000Z',
          deployment_id: config.deploymentId,
          host_id: null,
          edge_node_id: null,
        });
      case '/reconcile-host':
        await record('reconcile-host');
        return send(200, { deployment_id: config.deploymentId, host_id: config.hostId });
      case '/desired-state':
        await record('desired-state');
        return send(200, {
          desired_state: {
            deployment_id: config.deploymentId,
            edge_node_id: null,
            desired_generation: 1,
            desired_checksum: 'b'.repeat(64),
            fencing_epoch: 1,
            revision: {
              workloads: [{ code: 'site_core', desired_status: 'enabled', image: 'actium/site-core:0.1.0' }],
              public_endpoints: {},
            },
          },
        }, { etag: '"cold-commissioning-1"' });
      case '/site-authority-key':
        sitePublicJwk = structuredClone(body?.public_key_jwk ?? null);
        if (!sitePublicJwk) return send(400, { status: 'site_authority_key_invalid' });
        packageCache.clear();
        await record('site-authority-key', { key_ref: body?.key_ref ?? null });
        return send(200, { ok: true });
      case '/site-runtime-package': {
        const packageValue = materializePackage();
        const packageSha256 = createHash('sha256').update(JSON.stringify(packageValue)).digest('hex');
        await record('site-runtime-package', { republished, package_sha256: packageSha256 });
        return send(200, {
          package_sha256: packageSha256,
          package: packageValue,
          publication_id: packageValue.publication_id,
          runtime_organization_id: '22222222-2222-4222-8222-222222222222',
          desired_state_sha256: 'a'.repeat(64),
          contract_revision: 'site-runtime-canonical-scope-v2',
          generation: 1,
        });
      }
      case '/site-runtime-republish':
        republished = true;
        await record('site-runtime-republish', { republished });
        return send(200, {
          runtime_topology_published: true,
          organization_presentation_published: true,
        });
      case '/observed-state':
        await record('observed-state', {
          status: body?.status ?? null,
          observed_generation: body?.observed_generation ?? null,
        });
        return send(200, { ok: true });
      default:
        return send(404, { status: 'not_found' });
    }
  } catch (error) {
    await record('test-double-error', { error: String(error) });
    return send(500, { status: 'test_double_error' });
  }
});

server.listen(config.port, '0.0.0.0', async () => {
  await record('listening', { port: config.port });
  await writeFile(config.readyPath, `${config.port}\n`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => server.close(() => process.exit(0)));
}
