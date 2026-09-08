import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { strict as nodeAssert } from "node:assert";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import test from "node:test";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const manager = await readFile(join(root, "src", "main.ts"), "utf8");

test("Connectivity y Authority usan el gateway canónico y tienen páginas dedicadas", () => {
  assert.match(manager, /data-route="#\/connectivity"/);
  assert.match(manager, /data-route="#\/authority-fabric"/);
  assert.match(manager, /data-route="#\/host-enrollment"/);
  assert.match(manager, /function canonicalControlPlaneBase\(/);
  assert.match(manager, /service-resolution\?\$\{query\.toString\(\)\}/);
  assert.match(manager, /canonicalControlPlaneBase\(candidate\.endpoint\)/);
  assert.match(manager, /async function refreshAuthorityFabric\(/);
  assert.match(manager, /function renderAuthorityFabric\(/);
  assert.match(manager, /function renderHostEnrollment\(/);
});

test("Host Enrollment mantiene el orden de FSM y revalida readiness antes del ticket", () => {
  const ceremony = manager.slice(manager.indexOf("async function generateEnrollmentProof"));
  const order = [
    "setEnrollmentCeremonyStage(\"preflight\"",
    "await refreshControlPlane()",
    "setEnrollmentCeremonyStage(\"challenge\"",
    "host-enrollment-challenge",
    "setEnrollmentCeremonyStage(\"proof\"",
    "host-enrollment-complete",
    "setEnrollmentCeremonyStage(\"pending_apply\"",
    "enrollment_apply_signed_package",
    "setEnrollmentCeremonyStage(\"ack\"",
    "host-enrollment-confirm",
  ].map((value) => ceremony.indexOf(value));
  nodeAssert.ok(order.every((index) => index >= 0));
  nodeAssert.ok(order.every((index, position) => position === 0 || index > order[position - 1]));
  assert.match(ceremony, /hostEnrollmentTicket = ""/);
});

console.log("connectivity UI contract: ok");
