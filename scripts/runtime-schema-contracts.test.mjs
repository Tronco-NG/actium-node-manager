import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";

const dataPlaneRoot = resolve(import.meta.dirname, "../..");

async function read(relativePath) {
  return readFile(resolve(dataPlaneRoot, relativePath), "utf8");
}

async function migrations(service) {
  const root = resolve(dataPlaneRoot, `services/${service}/migrations`);
  const names = (await readdir(root)).filter((name) => name.endsWith(".sql")).sort();
  return (await Promise.all(names.map((name) => read(`services/${service}/migrations/${name}`)))).join("\n");
}

function assertRuntimeSafeMigration(sql, logicalSchema) {
  assert.doesNotMatch(sql, /\bcreate\s+schema\b/i);
  assert.doesNotMatch(sql, /\bcreate\s+(?:role|database)\b/i);
  assert.doesNotMatch(sql, /\balter\s+(?:role|database)\b/i);
  assert.doesNotMatch(sql, /\b(?:grant|revoke)\b/i);
  assert.doesNotMatch(sql, new RegExp(`\\b${logicalSchema}\\s*\\.`, "i"));
}

test("Site Core consume el binding SQL del Supervisor sin autoprovisionarse", async () => {
  const [config, database, compose, dockerfile, entrypoint, sql] = await Promise.all([
    read("services/site-core/src/config.ts"),
    read("services/site-core/src/database.ts"),
    read("compose.site-core.yml"),
    read("services/site-core/Dockerfile"),
    read("services/site-core/docker-entrypoint.sh"),
    migrations("site-core"),
  ]);

  assertRuntimeSafeMigration(sql, "site_core");
  assert.match(config, /ACTIUM_RUNTIME_DB_USER:\s*z\.string\(\)\.regex\(/);
  assert.match(config, /ACTIUM_RUNTIME_DB_SCHEMA:\s*z\.string\(\)\.regex\(/);
  assert.match(database, /options:\s*`-c search_path=\$\{config\.ACTIUM_RUNTIME_DB_SCHEMA\},public`/);
  assert.match(database, /site_core_database_binding_mismatch/);
  assert.doesNotMatch(database, /\b(?:create|alter)\s+(?:role|schema)\b/i);
  assert.doesNotMatch(database, /database-credentials\.json|DATABASE_ADMIN|provisionRuntimeRole/i);
  assert.doesNotMatch(entrypoint, /database-credentials\.json/);
  assert.match(dockerfile, /sed -i 's\/\\r\$\/\/' \/usr\/local\/bin\/actium-site-core-entrypoint/);
  assert.match(compose, /ACTIUM_RUNTIME_DB_SCHEMA:\s*\$\{ACTIUM_RUNTIME_DB_SCHEMA:\?Defina ACTIUM_RUNTIME_DB_SCHEMA\}/);
  assert.doesNotMatch(compose, /DATABASE_ADMIN|POSTGRES_ADMIN/);
});

test("Radio usa migrations y repositorio dentro del schema efectivo", async () => {
  const [config, database, repository, dockerfile, control, saf, sql] = await Promise.all([
    read("services/radio/src/config.ts"),
    read("services/radio/src/database.ts"),
    read("services/radio/src/repository.ts"),
    read("migrations/radio.Dockerfile"),
    read("compose.radio-control.yml"),
    read("compose.radio-saf.yml"),
    migrations("radio"),
  ]);

  assertRuntimeSafeMigration(sql, "radio");
  assert.doesNotMatch(sql, /\bcreate\s+extension\b/i);
  assert.doesNotMatch(repository, /\bradio\s*\.(?:floor_leases|presence_current|runtime_events|saf_messages)\b/i);
  assert.match(config, /ACTIUM_RUNTIME_DB_SCHEMA:\s*z\.string\(\)\.regex\(/);
  assert.match(database, /options:\s*`-c search_path=\$\{schema\},public`/);
  assert.match(dockerfile, /run-postgres-unit-migrations\.sh/);
  for (const compose of [control, saf]) {
    assert.match(compose, /ACTIUM_RUNTIME_DB_SCHEMA:\s*\$\{ACTIUM_RUNTIME_DB_SCHEMA:\?Defina ACTIUM_RUNTIME_DB_SCHEMA\}/);
    assert.match(compose, /entrypoint:\s*\[\/bin\/sh, \/usr\/local\/bin\/run-postgres-unit-migrations\.sh\]/);
    assert.doesNotMatch(compose, /exec migrate -path=\/migrations/);
  }
});

test("Supervisor conserva provisioning exclusivo y CREATE=f", async () => {
  const runtime = await read("installer/src-tauri/actium-node-core/src/runtime.rs");
  assert.match(runtime, /CREATE SCHEMA IF NOT EXISTS \{schema\} AUTHORIZATION \{role\}/);
  assert.match(runtime, /ALTER ROLE \{role\} IN DATABASE actium_fabric SET search_path TO \{schema\}, public/);
  assert.match(runtime, /GRANT CONNECT ON DATABASE actium_fabric TO \{role\}/);
  assert.doesNotMatch(runtime, /GRANT CREATE ON DATABASE actium_fabric/i);
});
