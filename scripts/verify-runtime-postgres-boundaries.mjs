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
const postgresContainer = `actium-runtime-pg-${suffix}`;
const network = `actium-runtime-net-${suffix}`;
const siteCoreImage = `actium/site-core-boundary:${suffix}`;
const radioMigrationImage = `actium/radio-migrations-boundary:${suffix}`;
const adminPassword = randomBytes(32).toString("hex");
const secrets = new Set([adminPassword]);
const temporaryRoots = [];
const siteCoreContainers = new Set();

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
    "exec", "-i", postgresContainer,
    "psql", "-v", "ON_ERROR_STOP=1", "-At", "-U", "postgres", "-d", database,
  ], { input: sql }).output;
}

function runtimeSql(runtime, sql, allowFailure = false) {
  return docker([
    "exec", "-e", `PGPASSWORD=${runtime.password}`, postgresContainer,
    "psql", "-h", "127.0.0.1", "-v", "ON_ERROR_STOP=1", "-At",
    "-U", runtime.user, "-d", "actium_fabric", "-c", sql,
  ], { allowFailure });
}

async function runtimeFixture(kind, label) {
  const password = randomBytes(32).toString("hex");
  const fixtureOrdinal = label === "a" ? "1" : "2";
  secrets.add(password);
  const root = await mkdtemp(join(tmpdir(), `actium-${kind}-${label}-`));
  const dataRoot = join(root, "data");
  temporaryRoots.push(root);
  await writeFile(join(root, "postgres_password"), `${password}\n`, { encoding: "utf8", mode: 0o600 });
  if (kind === "site") {
    await writeFile(join(root, "actium_site_bundle_public_key"), "preflight-public-key\n", { encoding: "utf8", mode: 0o600 });
    await writeFile(join(root, "site_core_install_token"), "preflight-install-token\n", { encoding: "utf8", mode: 0o600 });
  }
  return {
    kind,
    user: `u_${kind}_${label}_${suffix}`.slice(0, 63),
    schema: `unit_${kind}_${label}_${suffix}`.slice(0, 63),
    password,
    root,
    dataRoot,
    deploymentId: `00000000-0000-4000-8000-00000000010${fixtureOrdinal}`,
    siteId: `00000000-0000-4000-8000-00000000020${fixtureOrdinal}`,
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

function normalizedMount(path) {
  return path.replaceAll("\\", "/");
}

function runRadioMigrations(runtime) {
  docker([
    "run", "--rm", "--network", network,
    "-e", `ACTIUM_RUNTIME_DB_USER=${runtime.user}`,
    "-e", `ACTIUM_RUNTIME_DB_SCHEMA=${runtime.schema}`,
    "-e", "ACTIUM_FABRIC_POSTGRES_HOST=postgres",
    "-v", `${normalizedMount(runtime.root)}:/run/secrets:ro`,
    "--entrypoint", "/bin/sh", radioMigrationImage,
    "/usr/local/bin/run-postgres-unit-migrations.sh",
  ]);
}

function siteCoreContainerName(runtime) {
  return `actium-site-${runtime.schema}`.slice(0, 63);
}

function startSiteCore(runtime) {
  const container = siteCoreContainerName(runtime);
  siteCoreContainers.add(container);
  docker([
    "run", "-d", "--name", container, "--network", network,
    "-e", "NODE_ENV=production",
    "-e", "HOST=0.0.0.0",
    "-e", "PORT=8088",
    "-e", "DATABASE_HOST=postgres",
    "-e", "DATABASE_PORT=5432",
    "-e", "DATABASE_NAME=actium_fabric",
    "-e", `ACTIUM_RUNTIME_DB_USER=${runtime.user}`,
    "-e", `ACTIUM_RUNTIME_DB_SCHEMA=${runtime.schema}`,
    "-e", `ACTIUM_DEPLOYMENT_ID=${runtime.deploymentId}`,
    "-e", `ACTIUM_SITE_ID=${runtime.siteId}`,
    "-e", "POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password",
    "-e", "SITE_CORE_DATA_DIR=/var/lib/actium-site-core",
    "-e", "SITE_RUNTIME_TRUST_ANCHOR_FILE=/run/secrets/actium_site_bundle_public_key",
    "-e", "SITE_CORE_INSTALL_TOKEN_FILE=/run/secrets/site_core_install_token",
    "-e", "SITE_RUNTIME_EXPECTED_ISSUER=https://actium.invalid",
    "-e", "SITE_RUNTIME_EXPECTED_AUDIENCE=actium-site-core",
    "-e", "SITE_CORE_RUNTIME_ROLE=primary",
    "-e", "SITE_CORE_FENCING_STATE=active",
    "-e", "SITE_CORE_AUTHORITY_MODE=enabled",
    "-e", `SITE_CORE_EFFECTIVE_PRIMARY_DEPLOYMENT_ID=${runtime.deploymentId}`,
    "-e", "CORS_ORIGINS=https://localhost",
    "-v", `${normalizedMount(runtime.root)}:/run/secrets:ro`,
    "-v", `${normalizedMount(runtime.dataRoot)}:/var/lib/actium-site-core`,
    siteCoreImage,
  ]);

  let ready = false;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const probe = docker([
      "exec", container, "wget", "-q", "-O", "-", "http://127.0.0.1:8088/health/live",
    ], { allowFailure: true });
    if (probe.status === 0) {
      ready = true;
      break;
    }
    const state = docker(["inspect", "--format", "{{.State.Status}}", container], { allowFailure: true });
    if (state.output === "exited" || state.output === "dead") break;
    sleep(500);
  }
  if (!ready) {
    const logs = docker(["logs", container], { allowFailure: true }).output;
    throw new Error(`Site Core no quedo live para ${runtime.schema}: ${logs}`);
  }
}

function stopSiteCore(runtime) {
  const container = siteCoreContainerName(runtime);
  docker(["rm", "-f", container], { allowFailure: true });
  siteCoreContainers.delete(container);
}

function assertRuntimeBoundary(runtime, expectedTables) {
  assert.equal(
    runtimeSql(runtime, "select has_database_privilege(current_user, current_database(), 'CREATE');").output,
    "f",
  );
  assert.equal(runtimeSql(runtime, "select current_schema();").output, runtime.schema);
  assert.equal(
    runtimeSql(runtime, `select count(*) from pg_tables where schemaname = '${runtime.schema}' and tablename = any(array[${expectedTables.map((table) => `'${table}'`).join(",")}]);`).output,
    String(expectedTables.length),
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

function assertCrossIsolation(first, second, table) {
  const result = runtimeSql(first, `select count(*) from ${second.schema}.${table};`, true);
  assert.notEqual(result.status, 0, `${first.schema} puede leer ${second.schema}.${table}.`);
  assert.match(result.output, new RegExp(`permission denied for schema ${second.schema}`, "i"));
}

try {
  docker(["network", "create", "--internal", network]);
  docker([
    "run", "-d", "--name", postgresContainer, "--network", network, "--network-alias", "postgres",
    "-e", `POSTGRES_PASSWORD=${adminPassword}`, "postgres:17.6-alpine",
  ]);

  let postgresReady = false;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const probe = docker(["exec", postgresContainer, "pg_isready", "-U", "postgres"], { allowFailure: true });
    const logs = docker(["logs", postgresContainer], { allowFailure: true }).output;
    if (probe.status === 0 && logs.includes("PostgreSQL init process complete; ready for start up.")) {
      postgresReady = true;
      break;
    }
    sleep(500);
  }
  assert.equal(postgresReady, true, "PostgreSQL descartable no quedo ready.");
  adminSql("postgres", "CREATE DATABASE actium_fabric;\n");

  docker(["build", "--quiet", "--file", "services/site-core/Dockerfile", "--tag", siteCoreImage, "services/site-core"]);
  docker(["build", "--quiet", "--file", "migrations/radio.Dockerfile", "--tag", radioMigrationImage, "."]);

  const siteA = await runtimeFixture("site", "a");
  const siteB = await runtimeFixture("site", "b");
  const radioA = await runtimeFixture("radio", "a");
  const radioB = await runtimeFixture("radio", "b");
  for (const runtime of [siteA, siteB, radioA, radioB]) provision(runtime);

  startSiteCore(siteA);
  stopSiteCore(siteA);
  startSiteCore(siteA);
  startSiteCore(siteB);
  runRadioMigrations(radioA);
  runRadioMigrations(radioA);
  runRadioMigrations(radioB);
  runRadioMigrations(radioB);

  const siteTables = [
    "schema_migrations", "runtime_state", "terminal_bindings", "identity_projections",
    "auth_challenges", "revoked_tokens", "trusted_time", "audit_journal", "terminal_trust_projections",
  ];
  const radioTables = ["schema_migrations", "floor_leases", "presence_current", "saf_messages", "runtime_events"];
  assertRuntimeBoundary(siteA, siteTables);
  assertRuntimeBoundary(siteB, siteTables);
  assertRuntimeBoundary(radioA, radioTables);
  assertRuntimeBoundary(radioB, radioTables);

  assert.equal(adminSql("actium_fabric", "SELECT count(*) FROM pg_namespace WHERE nspname IN ('site_core','radio');"), "0");
  assertCrossIsolation(siteA, siteB, "runtime_state");
  assertCrossIsolation(radioA, radioB, "floor_leases");
  assertCrossIsolation(siteA, radioA, "floor_leases");
  assertCrossIsolation(radioA, siteA, "runtime_state");

  runtimeSql(siteA, "insert into trusted_time (singleton,max_seen_at) values (true,clock_timestamp()) on conflict (singleton) do update set max_seen_at=excluded.max_seen_at;");
  runtimeSql(radioA, "insert into runtime_events (event_id,organization_id,channel_id,terminal_id,binding_epoch,event_code) values ('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002','preflight','terminal-a',1,'preflight.ok');");
  assert.match(runtimeSql(radioA, "select gen_random_uuid();").output, /^[a-f0-9-]{36}$/i);

  console.log(JSON.stringify({
    status: "verified",
    postgres: "postgres:17.6-alpine",
    siteCoreMigrationRc: 0,
    radioMigrationRc: 0,
    databaseCreatePrivilege: false,
    globalSiteCoreSchema: false,
    globalRadioSchema: false,
    arbitrarySchemaDenied: true,
    idempotent: true,
    twoInstancesIsolated: true,
    crossProfileIsolation: true,
    dml: true,
  }, null, 2));
} finally {
  for (const container of siteCoreContainers) docker(["rm", "-f", container], { allowFailure: true });
  docker(["rm", "-f", postgresContainer], { allowFailure: true });
  docker(["image", "rm", "-f", siteCoreImage], { allowFailure: true });
  docker(["image", "rm", "-f", radioMigrationImage], { allowFailure: true });
  docker(["network", "rm", network], { allowFailure: true });
  await Promise.all(temporaryRoots.map((root) => rm(root, { recursive: true, force: true })));
}
