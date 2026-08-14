import { createHash } from "node:crypto";
import { readdir, readFile, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { lstat } from "node:fs/promises";

const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });
const BINARY_EXTENSIONS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".bmp",
  ".webp",
  ".ico",
  ".woff",
  ".woff2",
  ".ttf",
  ".otf",
  ".eot",
  ".pdf",
  ".zip",
  ".gz",
  ".xz",
  ".7z",
  ".jar",
  ".tar",
  ".tgz",
  ".bz2",
  ".so",
  ".dll",
  ".exe",
  ".class",
  ".bin",
]);

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

export function isLikelyTextFile(path, bytes) {
  const lastDot = path.lastIndexOf(".");
  const extension = lastDot >= 0 ? path.slice(lastDot).toLowerCase() : "";
  if (extension.length > 0 && BINARY_EXTENSIONS.has(extension)) return false;

  if (bytes.includes(0)) return false;

  const sampleLength = Math.min(bytes.length, 32_768);
  let suspiciousControlBytes = 0;
  for (let i = 0; i < sampleLength; i += 1) {
    const current = bytes[i];
    if (current < 0x09) {
      suspiciousControlBytes += 1;
    } else if (current > 0x0d && current < 0x20) {
      suspiciousControlBytes += 1;
    }
  }

  if (sampleLength > 0 && suspiciousControlBytes / sampleLength > 0.01) return false;

  try {
    UTF8_DECODER.decode(bytes);
    return true;
  } catch {
    return false;
  }
}

function normalizeLineEndings(text) {
  return text.replace(/\r\n/g, "\n").replace(/\r(?!\n)/g, "\n");
}

export async function canonicalizePayloadTextFiles(payloadRoot) {
  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries.sort((left, right) => compareUtf8(left.name, right.name))) {
      const candidate = join(directory, entry.name);
      const metadata = await lstat(candidate);
      if (metadata.isDirectory()) {
        await visit(candidate);
        continue;
      }
      if (!metadata.isFile()) continue;

      const rel = relative(payloadRoot, candidate).replaceAll("\\", "/");
      const bytes = await readFile(candidate);
      if (!isLikelyTextFile(rel, bytes)) continue;

      const source = UTF8_DECODER.decode(bytes);
      const normalized = normalizeLineEndings(source);
      if (normalized !== source) {
        await writeFile(candidate, normalized, "utf8");
      }
    }
  }

  await visit(payloadRoot);
}

export async function collectPayloadFiles(root) {
  const files = [];
  const rootDirectory = root;

  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => compareUtf8(left.name, right.name));
    for (const entry of entries) {
      const absolute = join(directory, entry.name);
      const metadata = await lstat(absolute);
      if (metadata.isSymbolicLink()) {
        throw new Error(`El payload contiene un enlace simbolico o reparse point: ${absolute}`);
      }
      if (metadata.isDirectory()) {
        await visit(absolute);
      } else if (metadata.isFile() && entry.name !== "PAYLOAD.json") {
        const path = relative(rootDirectory, absolute).replaceAll("\\", "/");
        if (path.startsWith("..") || path === "") {
          throw new Error(`Ruta no canonicalizada en payload: ${path}`);
        }
        const bytes = await readFile(absolute);
        files.push({ path, size: bytes.byteLength, sha256: sha256(bytes) });
      }
    }
  }

  await visit(root);
  files.sort((left, right) => compareUtf8(left.path, right.path));
  return files;
}

export function payloadTreeSha256(files) {
  const digest = createHash("sha256");
  const ordered = [...files].sort((left, right) => compareUtf8(left.path, right.path));
  for (const file of ordered) {
    digest.update(file.path, "utf8");
    digest.update("\0");
    digest.update(String(file.size), "utf8");
    digest.update("\0");
    digest.update(file.sha256, "utf8");
    digest.update("\0");
  }
  return digest.digest("hex");
}
