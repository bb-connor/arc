#!/usr/bin/env node
// Recomputes bundle-manifest.json for a fixture directory.
//
// Writes the real schema emitted by `internet_web3/artifacts.py::
// ArtifactStore.write_manifest`:
//
//   {
//     "schema": "chio.example.ioa-web3.bundle-manifest.v1",
//     "generated_at": <int epoch seconds>,
//     "files": ["path/a.json", ...],   // sorted relative paths
//     "sha256": {"path/a.json": "<hex>", ...}   // raw hex, no prefix
//   }
//
// Excludes bundle-manifest.json, run-result.json, review-result.json,
// matching the exclusion set in artifacts.py.

import { readFile, writeFile, readdir, stat } from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_FIXTURE = path.resolve(__dirname, "..", "tests", "fixtures", "good-bundle");

// Excluded by basename, matching `path.name not in excluded` in artifacts.py.
const EXCLUDED_BASENAMES = new Set([
  "bundle-manifest.json",
  "run-result.json",
  "review-result.json",
]);

async function listAllFiles(root) {
  const out = [];
  async function walk(dir) {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) await walk(full);
      else if (e.isFile()) out.push(full);
    }
  }
  await walk(root);
  return out;
}

async function main() {
  const fixture = process.argv[2] ? path.resolve(process.argv[2]) : DEFAULT_FIXTURE;
  const st = await stat(fixture).catch(() => null);
  if (!st || !st.isDirectory()) {
    console.error(`fixture not found: ${fixture}`);
    process.exit(2);
  }
  const files = (await listAllFiles(fixture))
    .map((f) => path.relative(fixture, f))
    .filter((f) => !EXCLUDED_BASENAMES.has(path.basename(f)))
    .sort();

  const sha256 = {};
  for (const relPath of files) {
    const abs = path.join(fixture, relPath);
    const body = await readFile(abs);
    sha256[relPath] = crypto.createHash("sha256").update(body).digest("hex");
  }

  const manifest = {
    schema: "chio.example.ioa-web3.bundle-manifest.v1",
    generated_at: Math.floor(Date.now() / 1000),
    files,
    sha256,
  };

  const outPath = path.join(fixture, "bundle-manifest.json");
  await writeFile(outPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  console.log(`stamped ${outPath}: ${files.length} entries`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
