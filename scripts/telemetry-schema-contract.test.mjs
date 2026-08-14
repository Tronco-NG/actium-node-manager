import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";

const dataPlaneRoot = resolve(import.meta.dirname, "../..");

async function read(relativePath) {
  return readFile(resolve(dataPlaneRoot, relativePath), "utf8");
}

test("migrations Telemetry operan en el schema efectivo", async () => {
  const migrationsRoot = resolve(dataPlaneRoot, "services/telemetry/migrations");
  const names = (await readdir(migrationsRoot)).filter((name) => name.endsWith(".sql")).sort();
  assert.deepEqual(names, [
    "0001_telemetry_plane.sql",
    "0002_location_projection_metadata.sql",
    "0003_ingest_quota_buckets.sql",
  ]);
  const migrations = (await Promise.all(names.map((name) => read(`services/telemetry/migrations/${name}`)))).join("\n");
  assert.doesNotMatch(migrations, /\bcreate\s+schema\b/i);
  assert.doesNotMatch(migrations, /\btelemetry\s*\./i);
  assert.doesNotMatch(migrations, /\bset\s+(?:local\s+)?search_path\b/i);
  assert.doesNotMatch(migrations, /\b(?:grant|revoke)\b/i);
});

test("runtime y auditoria Telemetry resuelven tablas por search_path", async () => {
  const repository = await read("services/telemetry/src/repository.ts");
  const audit = await read("installer/src-tauri/actium-node-core/assets/telemetry-audit.sql");
  const config = await read("services/telemetry/src/config.ts");
  const database = await read("services/telemetry/src/database.ts");

  assert.doesNotMatch(repository, /\btelemetry\s*\./i);
  assert.doesNotMatch(audit, /\btelemetry\s*\./i);
  assert.match(config, /ACTIUM_RUNTIME_DB_SCHEMA:\s*z\.string\(\)\.regex\(\/\^\[a-z\]/);
  assert.match(database, /options:\s*`-c search_path=\$\{schema\},public`/);
});

test("runner recibe un schema validado y no crea namespaces", async () => {
  const runner = await read("migrations/run-postgres-unit-migrations.sh");
  const compose = await read("compose.telemetry.yml");

  assert.match(runner, /safe_identifier "\$database_schema"/);
  assert.match(runner, /search_path=\$\{database_schema\}/);
  assert.doesNotMatch(runner, /create\s+schema/i);
  assert.match(compose, /ACTIUM_RUNTIME_DB_SCHEMA:\s*\$\{ACTIUM_RUNTIME_DB_SCHEMA:\?Defina ACTIUM_RUNTIME_DB_SCHEMA\}/);
  assert.match(compose, /entrypoint:\s*\[\/bin\/sh, \/usr\/local\/bin\/run-postgres-unit-migrations\.sh\]/);
});

test("Supervisor conserva CREATE=f y materializa el binding SQL", async () => {
  const runtime = await read("installer/src-tauri/actium-node-core/src/runtime.rs");
  assert.match(runtime, /CREATE SCHEMA IF NOT EXISTS \{schema\} AUTHORIZATION \{role\}/);
  assert.match(runtime, /ALTER ROLE \{role\} IN DATABASE actium_fabric SET search_path TO \{schema\}, public/);
  assert.match(runtime, /GRANT CONNECT ON DATABASE actium_fabric TO \{role\}/);
  assert.doesNotMatch(runtime, /GRANT CREATE ON DATABASE actium_fabric/i);
  assert.match(runtime, /values\.insert\("ACTIUM_RUNTIME_DB_SCHEMA", value\.clone\(\)\)/);
});
