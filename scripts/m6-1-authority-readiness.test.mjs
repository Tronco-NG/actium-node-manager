import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";

const root = resolve(import.meta.dirname, "..");
const manager = await readFile(resolve(root, "src/main.ts"), "utf8");
const service = await readFile(resolve(root, "src-tauri/actium-authority-service/src/main.rs"), "utf8");
const core = await readFile(resolve(root, "src-tauri/actium-node-core/src/trust_fabric.rs"), "utf8");
const cargo = await readFile(resolve(root, "src-tauri/Cargo.toml"), "utf8");

test("Manager consulta readiness efectivo antes de habilitar Host Enrollment", () => {
  assert.match(manager, /probeEnrollmentAuthority/);
  assert.match(manager, /host-enrollment-readiness/);
  assert.match(manager, /enrollmentAuthorityReadiness\.enrollmentReady/);
  assert.match(manager, /Bloqueado antes de consumir el ticket/);
  assert.doesNotMatch(manager, /window\.prompt/);
});

test("Authority Service separado es fail-closed y no genera material al arrancar", () => {
  assert.match(cargo, /actium-authority-service/);
  assert.match(service, /ServiceMode::Uninitialized/);
  assert.match(service, /AUTHORITY_BOOTSTRAP_PENDING/);
  assert.match(service, /AUTHORITY_SERVICE_REMOTE_BIND_REQUIRES_SERVICE_AUTH/);
  assert.match(service, /AUTHORITY_SERVICE_REMOTE_BIND_REQUIRES_TLS_TERMINATOR/);
  assert.match(service, /ACTIUM_AUTHORITY_TEST_FIXTURE/);
  assert.match(service, /AUTHORITY_TEST_FIXTURE_FORBIDDEN_IN_PRODUCTION/);
  assert.doesNotMatch(service, /initialize.*http|\/v1\/initialize/i);
});

test("Trust core selecciona signer por capability y verifica el mismo boundary", () => {
  assert.match(core, /pub fn sign_for_capability/);
  assert.match(core, /pub fn verify_for_capability/);
  assert.match(core, /TRUST_CAPABILITY_REJECTED/);
});

console.log("m6-1-authority-readiness: ok");
