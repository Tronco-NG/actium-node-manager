import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { cp, lstat, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const installerRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dataPlaneRoot = resolve(installerRoot, "..");
const targetRoot = join(installerRoot, "src-tauri", "resources", "node");
const include = [
  "VERSION",
  "README.md",
  "compose.fabric.yml",
  "compose.agent.yml",
  "compose.site-core.yml",
  "compose.telemetry.yml",
  "compose.radio-control.yml",
  "compose.radio-saf.yml",
  "compose.turn.yml",
  "compose.livekit.yml",
  "compose.connectivity.yml",
  "compose.observability.yml",
  "bootstrap.ps1",
  "bootstrap.sh",
  "install-node.ps1",
  "install-node.sh",
  "manage-node.ps1",
  "manage-node.sh",
  "verify-node.ps1",
  "verify-node.sh",
  "node.env.example",
  "contracts",
  "coturn",
  "connectivity",
  "docs",
  "livekit",
  "migrations",
  "nats",
  "observability",
  "postgres",
  "scripts",
  "services",
];

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function payloadFiles(root) {
  const files = [];

  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
    for (const entry of entries) {
      const absolute = join(directory, entry.name);
      const metadata = await lstat(absolute);
      if (metadata.isSymbolicLink()) {
        throw new Error(`El payload contiene un enlace simbolico o reparse point: ${absolute}`);
      }
      if (entry.isDirectory()) {
        await visit(absolute);
      } else if (entry.isFile() && entry.name !== "PAYLOAD.json") {
        const relative = absolute.slice(root.length + 1).replaceAll("\\", "/");
        if (relative.startsWith("/") || relative.split("/").some((part) => part === ".." || part === ".")) {
          throw new Error(`Ruta no canonicalizada en payload: ${relative}`);
        }
        const bytes = await readFile(absolute);
        files.push({ path: relative, size: bytes.byteLength, sha256: sha256(bytes) });
      }
    }
  }

  await visit(root);
  files.sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  return files;
}

function payloadTreeSha256(files) {
  const digest = createHash("sha256");
  for (const file of files) {
    digest.update(file.path, "utf8");
    digest.update("\0");
    digest.update(String(file.size), "utf8");
    digest.update("\0");
    digest.update(file.sha256, "utf8");
    digest.update("\0");
  }
  return digest.digest("hex");
}

function gitMetadata() {
  try {
    const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
      cwd: dataPlaneRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
    const sourceCommit = execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
    const status = execFileSync("git", ["status", "--porcelain", "--untracked-files=all"], {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
    return { sourceCommit, sourceDirty: status.length > 0 };
  } catch (error) {
    throw new Error(`No se pudo vincular el payload a Git: ${error.message}`);
  }
}

await rm(targetRoot, { recursive: true, force: true });
await mkdir(targetRoot, { recursive: true });

for (const entry of include) {
  const source = join(dataPlaneRoot, entry);
  const destination = join(targetRoot, entry);
  await cp(source, destination, {
    recursive: true,
    filter: (candidate) => {
      const normalized = candidate.replaceAll("\\", "/");
      return !normalized.includes("/node_modules/")
        && !normalized.includes("/target/")
        && !normalized.includes("/dist/")
        && !normalized.endsWith("/node.env")
        && !normalized.includes("/secrets/");
    },
  });
}

const version = (await readFile(join(dataPlaneRoot, "VERSION"), "utf8")).trim();
const files = await payloadFiles(targetRoot);
const treeSha256 = payloadTreeSha256(files);
const source = gitMetadata();
if (process.env.ACTIUM_REQUIRE_CLEAN_WORKTREE === "true" && source.sourceDirty) {
  throw new Error("El bundle Lab exige un working tree limpio; no se generara un candidato ambiguo.");
}
await writeFile(
  join(targetRoot, "PAYLOAD.json"),
  `${JSON.stringify({
    schema: 3,
    releaseVersion: version,
    files,
    treeSha256,
    siteRuntimeSchema: "1.1",
    generatedAt: new Date().toISOString(),
    sourceCommit: source.sourceCommit,
    sourceDirty: source.sourceDirty,
  }, null, 2)}\n`,
  "utf8",
);

console.log(`Payload Actium Data Plane ${version} schema 3 (${treeSha256.slice(0, 12)}) preparado en ${targetRoot}`);
