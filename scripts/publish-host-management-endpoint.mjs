import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const MANAGEMENT_GATEWAY_SCHEMA = 'actium.host.management.endpoint.v1';
export const MANAGEMENT_GATEWAY_DOMAIN_PREFIX = 'actium.host.management.endpoint.v1\n';

export function canonicalManagementEndpointPayload(descriptor) {
  const fields = {
    bindingEpoch: Number(descriptor.bindingEpoch),
    endpoint: String(descriptor.endpoint),
    expiresAt: String(descriptor.expiresAt),
    generation: Number(descriptor.generation),
    hostId: String(descriptor.hostId),
    issuedAt: String(descriptor.issuedAt),
    schema: MANAGEMENT_GATEWAY_SCHEMA,
    scheme: 'https',
    siteId: String(descriptor.siteId),
    status: String(descriptor.status || 'active'),
    tlsFingerprint: String(descriptor.tlsFingerprint).toLowerCase(),
  };
  const sortedKeys = Object.keys(fields).sort();
  const sorted = {};
  for (const k of sortedKeys) {
    sorted[k] = fields[k];
  }
  return JSON.stringify(sorted);
}

export function signDescriptor(payloadFields, privateKeyDerOrHex) {
  const canonicalJson = canonicalManagementEndpointPayload(payloadFields);
  const signableBytes = Buffer.concat([
    Buffer.from(MANAGEMENT_GATEWAY_DOMAIN_PREFIX, 'utf8'),
    Buffer.from(canonicalJson, 'utf8')
  ]);

  let privateKeyObj;
  if (typeof privateKeyDerOrHex === 'string') {
    const rawKey = Buffer.from(privateKeyDerOrHex.trim(), 'hex');
    privateKeyObj = crypto.createPrivateKey({
      key: Buffer.concat([
        Buffer.from('302e020100300506032b657004220420', 'hex'),
        rawKey
      ]),
      format: 'der',
      type: 'pkcs8'
    });
  } else {
    privateKeyObj = privateKeyDerOrHex;
  }

  const signature = crypto.sign(null, signableBytes, privateKeyObj);
  const signatureBase64Url = signature.toString('base64url');

  // Derive public key and key_id
  const publicKeyObj = crypto.createPublicKey(privateKeyObj);
  const exported = publicKeyObj.export({ format: 'der', type: 'spki' });
  const rawPub = exported.subarray(exported.length - 32);
  const signerKeyId = `sha256:${crypto.createHash('sha256').update(rawPub).digest('hex')}`;

  return {
    schema: MANAGEMENT_GATEWAY_SCHEMA,
    hostId: payloadFields.hostId,
    siteId: payloadFields.siteId,
    bindingEpoch: Number(payloadFields.bindingEpoch),
    scheme: 'https',
    endpoint: payloadFields.endpoint,
    tlsFingerprint: payloadFields.tlsFingerprint.toLowerCase(),
    generation: Number(payloadFields.generation),
    issuedAt: payloadFields.issuedAt,
    expiresAt: payloadFields.expiresAt,
    status: 'active',
    signerKeyId,
    signatureAlg: 'Ed25519',
    signature: signatureBase64Url
  };
}

export async function publishToCanonicalSupabase(signedDescriptor, supabaseUrl, apiKey) {
  const url = `${supabaseUrl.replace(/\/+$/, '')}/rest/v1/rpc/publish_actium_host_management_endpoint_v1`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'apikey': apiKey,
      'authorization': `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      p_host_id: signedDescriptor.hostId,
      p_management_endpoint: signedDescriptor
    })
  });

  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(`PUBLISH_FAILED (${response.status}): ${body.message || body.error || JSON.stringify(body)}`);
  }
  return body;
}

if (import.meta.url === `file:///${process.argv[1].replace(/\\/g, '/')}`) {
  const args = process.argv.slice(2);
  console.log('Actium Host Management Endpoint Publisher module loaded.');
}
