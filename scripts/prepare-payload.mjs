import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
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
  "coturn",
  "connectivity",
  "docs",
  "livekit",
  "migrations",
  "nats",
  "observability",
  "postgres",
  "services",
];

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
        && !normalized.endsWith("/node.env")
        && !normalized.includes("/secrets/");
    },
  });
}

const version = (await readFile(join(dataPlaneRoot, "VERSION"), "utf8")).trim();
await writeFile(
  join(targetRoot, "PAYLOAD.json"),
  `${JSON.stringify({ schema: 1, version, generatedAt: new Date().toISOString() }, null, 2)}\n`,
  "utf8",
);

console.log(`Payload Actium Data Plane ${version} preparado en ${targetRoot}`);
