import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const dataPlaneRoot = process.argv[2]
  ? resolve(process.argv[2])
  : resolve(import.meta.dirname, "../..");
const suffix = randomBytes(6).toString("hex");
const postgresContainer = `actium-p0-pg-${suffix}`;
const network = `actium-p0-net-${suffix}`;
const migrationImage = `actium/telemetry-migrations-p0:${suffix}`;
const adminPassword = randomBytes(32).toString("hex");
const secrets = new Set([adminPassword]);
const temporaryRoots = [];

function redact(value) {
  let output = String(value ?? "");
  for (const secret of secrets) output = output.replaceAll(secret, "[REDACTED]");
  return output;
}

function docker(args, options = {}) {
  const result = spawnSync("docker", args, {
    cwd: dataPlaneRoot,
    encoding: "utf8",
    input: options.input,
    maxBuffer: 16 * 1024 * 1024,
  });
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  if (result.error) throw new Error(`Docker no pudo ejecutarse: ${redact(result.error.message)}`);
  if (!options.allowFailure && result.status !== 0) {
    throw new Error(`Docker devolvio rc=${result.status}: ${redact(output).trim()}`);
  }
  return { status: result.status ?? 1, output: redact(output).trim() };
}

function sleep(milliseconds) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

function adminSql(database, sql) {
  return docker([
    "exec",
    "-i",
    postgresContainer,
    "psql",
    "-v",
    "ON_ERROR_STOP=1",
    "-At",
    "-U",
    "postgres",
    "-d",
    database,
  ], { input: sql }).output;
}

function runtimeSql(runtime, sql, allowFailure = false) {
  return docker([
    "exec",
    "-e",
    `PGPASSWORD=${runtime.password}`,
    postgresContainer,
    "psql",
    "-h",
    "127.0.0.1",
    "-v",
    "ON_ERROR_STOP=1",
    "-At",
    "-U",
    runtime.user,
    "-d",
    "actium_fabric",
    "-c",
    sql,
  ], { allowFailure });
}

async function runtimeFixture(label) {
  const password = randomBytes(32).toString("hex");
  secrets.add(password);
  const root = await mkdtemp(join(tmpdir(), `actium-p0-${label}-`));
  temporaryRoots.push(root);
  await writeFile(join(root, "postgres_password"), `${password}\n`, { encoding: "utf8", mode: 0o600 });
  return {
    user: `u_preflight_${label}`,
    schema: `unit_preflight_${label}`,
    password,
    secretsRoot: root,
  };
}

function provision(runtime) {
  adminSql("actium_fabric", `
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${runtime.user}') THEN
    CREATE ROLE ${runtime.user} LOGIN PASSWORD '${runtime.password}';
  END IF;
END $$;
CREATE SCHEMA ${runtime.schema} AUTHORIZATION ${runtime.user};
ALTER ROLE ${runtime.user} IN DATABASE actium_fabric SET search_path TO ${runtime.schema}, public;
GRANT CONNECT ON DATABASE actium_fabric TO ${runtime.user};
`);
}

function runMigrations(runtime) {
  const mount = `${runtime.secretsRoot.replaceAll("\\", "/")}:/run/secrets:ro`;
  docker([
    "run",
    "--rm",
    "--network",
    network,
    "-e",
    `ACTIUM_RUNTIME_DB_USER=${runtime.user}`,
    "-e",
    `ACTIUM_RUNTIME_DB_SCHEMA=${runtime.schema}`,
    "-e",
    "ACTIUM_FABRIC_POSTGRES_HOST=postgres",
    "-v",
    mount,
    "--entrypoint",
    "/bin/sh",
    migrationImage,
    "/usr/local/bin/run-postgres-unit-migrations.sh",
  ]);
}

function assertRuntimeBoundary(runtime) {
  assert.equal(
    runtimeSql(runtime, "select has_database_privilege(current_user, current_database(), 'CREATE');").output,
    "f",
  );
  assert.equal(runtimeSql(runtime, "select current_schema();").output, runtime.schema);
  assert.equal(
    runtimeSql(runtime, `select count(*) from pg_tables where schemaname = '${runtime.schema}' and tablename in ('gps_batches','gps_points','terminal_location_current','terminal_presence_current','dead_letters','ingest_quota_buckets');`).output,
    "6",
  );

  const ownedObjects = adminSql("actium_fabric", `
SELECT n.nspname || '.' || c.relname
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_roles r ON r.oid = c.relowner
WHERE r.rolname = '${runtime.user}'
  AND c.relkind IN ('r', 'p', 'S', 'v', 'm')
ORDER BY 1;
`).split(/\r?\n/u).map((line) => line.trim()).filter(Boolean);
  assert.ok(ownedObjects.length > 0);
  assert.ok(ownedObjects.every((name) => name.startsWith(`${runtime.schema}.`)), ownedObjects.join(", "));

  const arbitrary = runtimeSql(runtime, `create schema ${runtime.schema}_arbitrary;`, true);
  assert.notEqual(arbitrary.status, 0, "La runtime unit obtuvo CREATE sobre la database.");
  assert.match(arbitrary.output, /permission denied for database actium_fabric/i);
}

let verdict = "rejected";
try {
  docker(["network", "create", "--internal", network]);
  docker([
    "run",
    "-d",
    "--name",
    postgresContainer,
    "--network",
    network,
    "--network-alias",
    "postgres",
    "-e",
    `POSTGRES_PASSWORD=${adminPassword}`,
    "postgres:17.6-alpine",
  ]);

  let ready = false;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const probe = docker([
      "exec",
      postgresContainer,
      "pg_isready",
      "-U",
      "postgres",
    ], { allowFailure: true });
    const query = probe.status === 0
      ? docker([
        "exec",
        postgresContainer,
        "psql",
        "-At",
        "-U",
        "postgres",
        "-d",
        "postgres",
        "-c",
        "select 1",
      ], { allowFailure: true })
      : { status: 1 };
    if (query.status === 0) {
      ready = true;
      break;
    }
    sleep(500);
  }
  assert.equal(ready, true, "PostgreSQL descartable no quedo ready.");

  adminSql("postgres", "CREATE DATABASE actium_fabric;\n");
  docker([
    "build",
    "--quiet",
    "--file",
    "migrations/telemetry.Dockerfile",
    "--tag",
    migrationImage,
    ".",
  ]);

  const first = await runtimeFixture("a");
  const second = await runtimeFixture("b");
  provision(first);
  provision(second);

  runMigrations(first);
  runMigrations(first);
  runMigrations(second);
  runMigrations(second);

  assertRuntimeBoundary(first);
  assertRuntimeBoundary(second);
  assert.equal(
    adminSql("actium_fabric", "SELECT count(*) FROM pg_namespace WHERE nspname = 'telemetry';"),
    "0",
  );

  const crossAccess = runtimeSql(first, `select count(*) from ${second.schema}.gps_batches;`, true);
  assert.notEqual(crossAccess.status, 0, "Dos instancias Telemetry pueden accederse entre si.");
  assert.match(crossAccess.output, /permission denied for schema unit_preflight_b/i);

  verdict = "verified";
  console.log(JSON.stringify({
    status: verdict,
    postgres: "postgres:17.6-alpine",
    migrationRc: 0,
    databaseCreatePrivilege: false,
    globalTelemetrySchema: false,
    arbitrarySchemaDenied: true,
    idempotent: true,
    twoInstancesIsolated: true,
  }, null, 2));
} finally {
  docker(["rm", "-f", postgresContainer], { allowFailure: true });
  docker(["image", "rm", "-f", migrationImage], { allowFailure: true });
  docker(["network", "rm", network], { allowFailure: true });
  await Promise.all(temporaryRoots.map((root) => rm(root, { recursive: true, force: true })));
}
