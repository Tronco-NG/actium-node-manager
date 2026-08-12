import { createHash } from "node:crypto";
import { cp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const installerRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dataPlaneRoot = resolve(installerRoot, "..");
const targetRoot = join(installerRoot, "src-tauri", "resources", "node");
const include = [
  "VERSION",
  "README.md",
  "compose.yml",
  "compose.build.yml",
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

async function payloadContentSha256(root) {
  const files = [];

  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const absolute = join(directory, entry.name);
      if (entry.isDirectory()) {
        await visit(absolute);
      } else if (entry.isFile() && entry.name !== "PAYLOAD.json") {
        files.push(absolute);
      }
    }
  }

  await visit(root);
  const digest = createHash("sha256");
  for (const absolute of files) {
    const relative = absolute.slice(root.length + 1).replaceAll("\\", "/");
    digest.update(relative, "utf8");
    digest.update("\0");
    digest.update(await readFile(absolute));
    digest.update("\0");
  }
  return digest.digest("hex");
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
const contentSha256 = await payloadContentSha256(targetRoot);
await writeFile(
  join(targetRoot, "PAYLOAD.json"),
  `${JSON.stringify({
    schema: 2,
    version,
    contentSha256,
    siteRuntimeSchema: "1.1",
    generatedAt: new Date().toISOString(),
  }, null, 2)}\n`,
  "utf8",
);

console.log(`Payload Actium Data Plane ${version} preparado en ${targetRoot}`);
