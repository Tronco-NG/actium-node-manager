import { readFile } from "node:fs/promises";
import { strict as assert } from "node:assert";

const root = new URL("..", import.meta.url);
const read = (file) => readFile(new URL(file, root), "utf8");
const transport = await read("src/storageTransport.ts");
const main = await read("src/main.ts");

assert.match(transport, /STORAGE_TRANSPORT_PROTOCOL = ["']actium\.storage\.transport["']/);
assert.match(transport, /STORAGE_TRANSPORT_VERSION = 1/);
for (const field of ["messageId", "idempotencyKey", "issuedAt", "expiresAt", "scope", "signerKeyId", "signature"]) {
  assert.match(transport, new RegExp(`\\b${field}\\b`), `transport envelope missing ${field}`);
}
assert.match(transport, /validateStorageTransportEnvelope/);
assert.match(transport, /STORAGE_TRANSPORT_SIGNATURE_REQUIRED/);
assert.match(transport, /STORAGE_TRANSPORT_SCOPE_INVALID/);
assert.match(transport, /STORAGE_CENTER_TRANSPORT_UNAVAILABLE/);
assert.match(transport, /STORAGE_CENTER_TRANSPORT_URL_UNSAFE/);
assert.match(transport, /envelope\.protocol !== STORAGE_TRANSPORT_PROTOCOL/);
assert.match(transport, /publishDiscovery/);
assert.match(transport, /publishIntent/);
assert.match(transport, /fetchApproval/);
assert.doesNotMatch(transport, /service_role/i);
assert.match(main, /deploymentId: bootstrapValidation\?\.deploymentId \?\? installation\.deploymentId \?\? ""/);
assert.doesNotMatch(main, /deploymentId:\s*["']{2}[,}]/);

const runtime = await import(new URL("../src/storageTransport.ts", import.meta.url));
assert.throws(() => runtime.validateCenterStorageTransportUrl("http://10.77.10.226:8787"), /STORAGE_CENTER_TRANSPORT_URL_UNSAFE/);
assert.equal(runtime.validateCenterStorageTransportUrl("http://127.0.0.1:8787/"), "http://127.0.0.1:8787");
const base = Math.floor(Date.now() / 1000);
const envelope = {
  protocol: runtime.STORAGE_TRANSPORT_PROTOCOL,
  version: runtime.STORAGE_TRANSPORT_VERSION,
  messageType: "storage_grant_intent",
  messageId: "message-1",
  idempotencyKey: "intent-1",
  issuedAt: base,
  expiresAt: base + 60,
  scope: { clientId: "client", organizationId: "org", siteId: "site", hostId: "host", hostInstallationId: "install", deploymentId: "deployment", capability: "telemetry" },
  payload: {},
  signerKeyId: "host-key",
  signature: "signature",
};
runtime.validateStorageTransportEnvelope(envelope, base);
assert.throws(() => runtime.validateStorageTransportEnvelope({ ...envelope, signature: "" }, base), /STORAGE_TRANSPORT_SIGNATURE_REQUIRED/);
const calls = [];
const approvalEnvelope = { ...envelope, messageType: "storage_grant_approval", messageId: "approval-1", payload: { ...envelope.payload, intentId: "intent-1", idempotencyKey: "intent-1", organizationId: "org", siteId: "site", hostId: "host", hostInstallationId: "install", deploymentId: "deployment", capability: "telemetry" }, signature: "center-signature" };
const client = new runtime.HttpStorageCenterTransport("https://center.example", {
  fetchImpl: async (input) => {
    calls.push(String(input));
    return { ok: true, status: 200, json: async () => calls.at(-1).endsWith("/approval") ? { envelope: approvalEnvelope, approval: { payload: "claims", signature: "approval-signature" }, token: "token" } : { status: "pending" } };
  },
});
assert.deepEqual(await client.publishIntent(envelope), { status: "pending" });
const approval = await client.fetchApproval("intent-1", envelope.scope);
assert.equal(approval.token, "token");
assert.deepEqual(calls, ["https://center.example/intents", "https://center.example/intents/intent-1/approval"]);
console.log("storage phase 5 contract: ok");
