// Client-side bundle loading + validation.
//
// The provider fetches four eager artifacts (manifest, summary, review,
// topology), validates their shapes, and exposes a lazy fetchArtifact(path)
// for everything else. Errors are surfaced via a BundleLoadError; the
// top-level error boundary renders them into a visible banner.

import type { Bundle, Manifest, Summary, ReviewResult, Topology, Org } from "./types";
import { matchesManifestHash, sha256Hex } from "./hash";

export class BundleLoadError extends Error {
  readonly status: number;
  readonly path: string;
  constructor(message: string, status: number, path: string) {
    super(message);
    this.name = "BundleLoadError";
    this.status = status;
    this.path = path;
  }
}

export interface LoadedArtifact<T = unknown> {
  body: T;
  bytes: Uint8Array;
}

/**
 * Encode each segment of a relative path so it survives being dropped into
 * the `/api/bundle/...` URL. Slashes between segments are preserved literally.
 */
export function encodeBundlePath(rel: string): string {
  return rel.split("/").map((s) => encodeURIComponent(s)).join("/");
}

async function fetchJson<T>(path: string): Promise<LoadedArtifact<T>> {
  const res = await fetch(`/api/bundle/${encodeBundlePath(path)}`, { cache: "no-store" });
  if (!res.ok) {
    throw new BundleLoadError(
      `Failed to fetch ${path}: HTTP ${res.status}`,
      res.status,
      path,
    );
  }
  const buf = await res.arrayBuffer();
  const bytes = new Uint8Array(buf);
  try {
    const text = new TextDecoder().decode(bytes);
    const body = JSON.parse(text) as T;
    return { body, bytes };
  } catch (err) {
    throw new BundleLoadError(
      `Failed to parse ${path} as JSON: ${err instanceof Error ? err.message : String(err)}`,
      0,
      path,
    );
  }
}

function validateManifest(value: unknown): Manifest {
  if (!value || typeof value !== "object") {
    throw new BundleLoadError("manifest: not an object", 0, "bundle-manifest.json");
  }
  const v = value as Record<string, unknown>;
  if (typeof v["schema"] !== "string") {
    throw new BundleLoadError("manifest.schema missing or not a string", 0, "bundle-manifest.json");
  }
  if (typeof v["generated_at"] !== "number") {
    throw new BundleLoadError("manifest.generated_at missing or not a number", 0, "bundle-manifest.json");
  }
  if (!Array.isArray(v["files"])) {
    throw new BundleLoadError("manifest.files missing or not an array", 0, "bundle-manifest.json");
  }
  for (const f of v["files"]) {
    if (typeof f !== "string") {
      throw new BundleLoadError("manifest.files entry not a string", 0, "bundle-manifest.json");
    }
  }
  const sha = v["sha256"];
  if (!sha || typeof sha !== "object" || Array.isArray(sha)) {
    throw new BundleLoadError("manifest.sha256 missing or not an object", 0, "bundle-manifest.json");
  }
  for (const [key, hex] of Object.entries(sha as Record<string, unknown>)) {
    if (typeof hex !== "string") {
      throw new BundleLoadError(`manifest.sha256[${key}] not a string`, 0, "bundle-manifest.json");
    }
  }
  return value as Manifest;
}

function validateSummary(value: unknown): Summary {
  if (!value || typeof value !== "object") {
    throw new BundleLoadError("summary: not an object", 0, "summary.json");
  }
  const v = value as Record<string, unknown>;
  for (const key of ["schema", "example", "order_id"]) {
    if (typeof v[key] !== "string") {
      throw new BundleLoadError(`summary.${key} missing or not a string`, 0, "summary.json");
    }
  }
  if (!v["receipt_counts_by_boundary"] || typeof v["receipt_counts_by_boundary"] !== "object") {
    throw new BundleLoadError("summary.receipt_counts_by_boundary missing", 0, "summary.json");
  }
  return value as Summary;
}

function validateReview(value: unknown): ReviewResult {
  if (!value || typeof value !== "object") {
    throw new BundleLoadError("review-result: not an object", 0, "review-result.json");
  }
  const v = value as Record<string, unknown>;
  if (typeof v["ok"] !== "boolean") {
    throw new BundleLoadError("review-result.ok missing or not a boolean", 0, "review-result.json");
  }
  if (typeof v["schema"] !== "string") {
    // schema is optional in older runs; tolerate, but require bundle.
  }
  if (typeof v["bundle"] !== "string") {
    throw new BundleLoadError("review-result.bundle missing", 0, "review-result.json");
  }
  if (!Array.isArray(v["errors"])) {
    throw new BundleLoadError("review-result.errors missing or not an array", 0, "review-result.json");
  }
  return value as ReviewResult;
}

function validateTopology(value: unknown): Topology {
  if (!value || typeof value !== "object") {
    throw new BundleLoadError("topology: not an object", 0, "chio/topology.json");
  }
  const v = value as Record<string, unknown>;
  // The bundle topology uses `organizations` (array) as its canonical source.
  // The demo-side `orgs` map is filled in by mergeTopology from the array.
  // We accept either `orgs` (object) or `organizations` (array) here.
  if (v["orgs"] && typeof v["orgs"] === "object") {
    const orgs = v["orgs"] as Record<string, unknown>;
    for (const [id, org] of Object.entries(orgs)) {
      if (!org || typeof org !== "object") {
        throw new BundleLoadError(`topology.orgs[${id}] not an object`, 0, "chio/topology.json");
      }
      const o = org as Partial<Org>;
      if (typeof o.name !== "string") {
        throw new BundleLoadError(`topology.orgs[${id}].name missing`, 0, "chio/topology.json");
      }
    }
  } else if (!Array.isArray(v["organizations"])) {
    throw new BundleLoadError(
      "topology.orgs missing and topology.organizations not an array",
      0,
      "chio/topology.json",
    );
  }
  return value as Topology;
}

export interface LoadedBundle {
  bundle: Omit<Bundle, "beats">;
  /**
   * Path -> computed-hex-hash map for the eager files. Populated on success
   * with the hashes that were verified against the manifest.
   */
  hashes: Map<string, string>;
  /**
   * Path -> parsed body cache for the eager files. Lets the provider seed
   * its artifact cache without re-fetching anything.
   */
  bodies: Map<string, unknown>;
}

/**
 * Verify a fetched eager artifact's bytes against the manifest BEFORE its
 * body is published anywhere. Closes the TOCTOU gap that would otherwise
 * exist if we hashed via a separate second fetch.
 *
 * `review-result.json` is intentionally excluded from `manifest.sha256` by
 * `artifacts.py` (the verifier writes it after the manifest is sealed), so
 * its bytes cannot be authenticated. We still load it for advisory display
 * but must NOT use any of its fields to drive a fail-closed decision.
 */
async function verifyAgainstManifest(
  manifest: Manifest,
  path: string,
  bytes: Uint8Array,
  hashes: Map<string, string>,
): Promise<void> {
  const expected = manifest.sha256[path];
  if (!expected) {
    if (path === "review-result.json") return;
    throw new BundleLoadError(
      `manifest missing sha256 entry for required eager file ${path}`,
      0,
      path,
    );
  }
  const hex = await sha256Hex(bytes);
  hashes.set(path, hex);
  if (!matchesManifestHash(expected, hex)) {
    throw new BundleLoadError(
      `eager artifact ${path} hash mismatch (expected ${expected}, computed ${hex})`,
      0,
      path,
    );
  }
}

export async function loadEagerBundle(): Promise<LoadedBundle> {
  // Manifest first; everything else references it.
  const manifestArt = await fetchJson<unknown>("bundle-manifest.json");
  const manifest = validateManifest(manifestArt.body);

  const [summaryArt, reviewArt, topologyArt] = await Promise.all([
    fetchJson<unknown>("summary.json"),
    fetchJson<unknown>("review-result.json"),
    fetchJson<unknown>("chio/topology.json"),
  ]);

  // Verify hashes on the EXACT bytes we just fetched, before we expose any
  // of those bodies to UI state. If a manifest-listed artifact mismatches
  // (or is missing from the manifest entirely, except for review-result),
  // we throw and the provider transitions to status="error".
  const hashes = new Map<string, string>();
  await Promise.all([
    verifyAgainstManifest(manifest, "summary.json", summaryArt.bytes, hashes),
    verifyAgainstManifest(manifest, "review-result.json", reviewArt.bytes, hashes),
    verifyAgainstManifest(manifest, "chio/topology.json", topologyArt.bytes, hashes),
  ]);

  // Validate shapes only on bytes that have already passed hash verification.
  const summary = validateSummary(summaryArt.body);
  const review = validateReview(reviewArt.body);
  const topology = validateTopology(topologyArt.body);

  const bodies = new Map<string, unknown>([
    ["summary.json", summary],
    ["review-result.json", review],
    ["chio/topology.json", topology],
    ["bundle-manifest.json", manifest],
  ]);

  return {
    bundle: { manifest, summary, review, topology },
    hashes,
    bodies,
  };
}

/**
 * Deterministic digest of the manifest's sha256 map. Used by the top bar so
 * operators can eyeball whether two runs produced the same bundle without
 * comparing every file hash individually.
 */
export async function computeBundleDigest(manifest: Manifest): Promise<string> {
  const entries = Object.entries(manifest.sha256).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const canonical = JSON.stringify(entries);
  const bytes = new TextEncoder().encode(canonical);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const out = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < out.length; i += 1) {
    const byte = out[i] ?? 0;
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}
