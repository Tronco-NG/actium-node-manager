import { chmod, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const contractPath = join(dirname(fileURLToPath(import.meta.url)), "payload-unix-executables.txt");
export const payloadUnixExecutables = Object.freeze(
  (await readFile(contractPath, "utf8"))
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#")),
);

export async function applyPayloadUnixModes(payloadRoot) {
  for (const relativePath of payloadUnixExecutables) {
    const absolutePath = join(payloadRoot, relativePath);
    const source = await readFile(absolutePath, "utf8");
    await writeFile(absolutePath, source.replaceAll("\r\n", "\n"), "utf8");
    await chmod(absolutePath, 0o755);
  }
}

export async function verifyPayloadUnixModes(payloadRoot) {
  const failures = [];
  for (const relativePath of payloadUnixExecutables) {
    const metadata = await stat(join(payloadRoot, relativePath));
    if ((metadata.mode & 0o111) === 0) {
      failures.push(relativePath);
    }
  }
  if (failures.length > 0) {
    throw new Error(`Scripts Unix sin bit ejecutable en el payload empaquetado: ${failures.join(", ")}`);
  }
}
