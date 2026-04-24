"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

import type { Bundle, Manifest, Verdict } from "@/lib/types";
import {
  BundleLoadError,
  computeBundleDigest,
  encodeBundlePath,
  loadEagerBundle,
} from "@/lib/bundle";
import { matchesManifestHash, sha256Hex } from "@/lib/hash";
import { BEATS } from "@/lib/beats";

export type BundleStatus = "idle" | "loading" | "ready" | "error";

export interface BundleContextValue {
  status: BundleStatus;
  error: BundleLoadError | null;
  bundle: Bundle | null;
  /** Fetch an artifact body by its manifest path. Cached. */
  fetchArtifact: (path: string) => Promise<unknown>;
  /** Get a computed hash for a path if we have fetched it. */
  computedHashFor: (path: string) => string | undefined;
  /** True if any hash mismatch has been observed. */
  hashMismatch: boolean;
  /** First mismatched path (for display in the TopBar FAIL reason). */
  firstMismatchPath: string | null;
  /** Effective verdict, factoring in any runtime override (hash mismatch flips PASS -> FAIL). */
  effectiveVerdict: Verdict;
  /** Stable digest of the manifest sha256 map. Used as "bundle id". */
  bundleDigest: string | null;
}

const BundleContext = createContext<BundleContextValue | null>(null);

interface ProviderProps {
  children: ReactNode;
}

export function BundleProvider({ children }: ProviderProps): JSX.Element {
  const [status, setStatus] = useState<BundleStatus>("idle");
  const [error, setError] = useState<BundleLoadError | null>(null);
  const [bundle, setBundle] = useState<Bundle | null>(null);
  const [hashMismatch, setHashMismatch] = useState<boolean>(false);
  const [firstMismatchPath, setFirstMismatchPath] = useState<string | null>(null);
  const [bundleDigest, setBundleDigest] = useState<string | null>(null);

  // Artifact body cache and in-flight promise dedupe.
  const cacheRef = useRef<Map<string, unknown>>(new Map());
  const inflightRef = useRef<Map<string, Promise<unknown>>>(new Map());
  const hashesRef = useRef<Map<string, string>>(new Map());

  useEffect(() => {
    let cancelled = false;
    setStatus("loading");
    loadEagerBundle()
      .then(async (loaded) => {
        if (cancelled) return;
        const { bundle: base } = loaded;
        const initial: Bundle = {
          ...base,
          beats: [...BEATS],
        };
        setBundle(initial);
        try {
          const digest = await computeBundleDigest(initial.manifest);
          if (!cancelled) setBundleDigest(digest);
        } catch {
          // Digest is best-effort for display; don't fail the bundle load on it.
        }

        // Verify the eager artifacts against the manifest. If any eager fetch
        // or hash check fails, flip status to error so the banner surfaces it.
        const eagerOk = await verifyEagerHashes(
          initial.manifest,
          cacheRef,
          hashesRef,
          (path) => {
            setHashMismatch(true);
            setFirstMismatchPath((prev) => prev ?? path);
          },
        );

        if (cancelled) return;
        if (!eagerOk) {
          setError(
            new BundleLoadError(
              "Eager bundle verification failed. See console for details.",
              0,
              "bundle-manifest.json",
            ),
          );
          setStatus("error");
          return;
        }
        setStatus("ready");
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        const asErr =
          err instanceof BundleLoadError
            ? err
            : new BundleLoadError(
                err instanceof Error ? err.message : String(err),
                0,
                "bundle-manifest.json",
              );
        setError(asErr);
        setStatus("error");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const fetchArtifact = useCallback(async (path: string): Promise<unknown> => {
    const cached = cacheRef.current.get(path);
    if (cached !== undefined) return cached;
    const inflight = inflightRef.current.get(path);
    if (inflight) return inflight;

    const p = (async () => {
      const res = await fetch(`/api/bundle/${encodeBundlePath(path)}`, { cache: "no-store" });
      if (!res.ok) {
        throw new BundleLoadError(`fetch ${path} -> ${res.status}`, res.status, path);
      }
      const buf = await res.arrayBuffer();
      const bytes = new Uint8Array(buf);
      const text = new TextDecoder().decode(bytes);
      const body: unknown = JSON.parse(text);
      cacheRef.current.set(path, body);

      // Verify against manifest.
      const expected = bundle?.manifest.sha256[path];
      if (expected) {
        const hex = await sha256Hex(bytes);
        hashesRef.current.set(path, hex);
        if (!matchesManifestHash(expected, hex)) {
          setHashMismatch(true);
          setFirstMismatchPath((prev) => prev ?? path);
        }
      }
      return body;
    })();
    inflightRef.current.set(path, p);
    try {
      const result = await p;
      return result;
    } finally {
      inflightRef.current.delete(path);
    }
  }, [bundle]);

  const computedHashFor = useCallback((path: string): string | undefined => {
    return hashesRef.current.get(path);
  }, []);

  const effectiveVerdict = useMemo<Verdict>(() => {
    if (!bundle) return "PASS";
    if (hashMismatch) return "FAIL";
    return bundle.review.ok ? "PASS" : "FAIL";
  }, [bundle, hashMismatch]);

  const value = useMemo<BundleContextValue>(
    () => ({
      status,
      error,
      bundle,
      fetchArtifact,
      computedHashFor,
      hashMismatch,
      firstMismatchPath,
      effectiveVerdict,
      bundleDigest,
    }),
    [
      status,
      error,
      bundle,
      fetchArtifact,
      computedHashFor,
      hashMismatch,
      firstMismatchPath,
      effectiveVerdict,
      bundleDigest,
    ],
  );

  return <BundleContext.Provider value={value}>{children}</BundleContext.Provider>;
}

async function verifyEagerHashes(
  manifest: Manifest,
  cacheRef: React.MutableRefObject<Map<string, unknown>>,
  hashesRef: React.MutableRefObject<Map<string, string>>,
  onMismatch: (path: string) => void,
): Promise<boolean> {
  // bundle-manifest.json, run-result.json, and review-result.json are
  // excluded from `manifest.sha256` by artifacts.py (see `excluded` set), so
  // they cannot self-verify. Every other eager artifact must be a manifest
  // entry and must hash-match.
  const eagerVerifiable = ["summary.json", "chio/topology.json"];
  let ok = true;
  for (const path of eagerVerifiable) {
    const expected = manifest.sha256[path];
    if (typeof expected !== "string") {
      // Missing manifest entry for a required file is fail-closed.
      console.error(`manifest missing sha256 entry for required eager file: ${path}`);
      ok = false;
      continue;
    }
    try {
      const res = await fetch(`/api/bundle/${encodeBundlePath(path)}`, { cache: "no-store" });
      if (!res.ok) {
        console.error(`eager fetch ${path} -> HTTP ${res.status}`);
        ok = false;
        continue;
      }
      const buf = await res.arrayBuffer();
      const bytes = new Uint8Array(buf);
      const hex = await sha256Hex(bytes);
      hashesRef.current.set(path, hex);
      try {
        cacheRef.current.set(path, JSON.parse(new TextDecoder().decode(bytes)));
      } catch {
        // JSON is a precondition for eager artifacts; skip caching if parse fails.
      }
      if (!matchesManifestHash(expected, hex)) {
        // Eager artifacts are foundational (summary, topology). A hash
        // mismatch here is a fail-closed event: surface it via the
        // mismatch callback AND propagate as a load failure so the
        // provider transitions to status="error" instead of rendering
        // tampered data with a flipped verdict badge.
        onMismatch(path);
        ok = false;
      }
    } catch (err) {
      console.error(`eager fetch ${path} threw`, err);
      ok = false;
    }
  }
  return ok;
}

export function useBundle(): BundleContextValue {
  const ctx = useContext(BundleContext);
  if (!ctx) {
    throw new Error("useBundle must be used within a BundleProvider");
  }
  return ctx;
}
