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

import type { Bundle, Verdict } from "@/lib/types";
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
        // loadEagerBundle has already verified each manifest-listed eager
        // artifact's bytes against manifest.sha256 BEFORE returning, so the
        // bodies in `loaded.bundle` are safe to publish. Seed the artifact
        // body cache and the computed-hash map from the same bytes that
        // were verified, so later fetchArtifact() calls do not re-fetch
        // and any UI rendering uses authenticated bytes only.
        for (const [path, body] of loaded.bodies.entries()) {
          cacheRef.current.set(path, body);
        }
        for (const [path, hex] of loaded.hashes.entries()) {
          hashesRef.current.set(path, hex);
        }
        const initial: Bundle = {
          ...loaded.bundle,
          beats: [...BEATS],
        };
        setBundle(initial);
        try {
          const digest = await computeBundleDigest(initial.manifest);
          if (!cancelled) setBundleDigest(digest);
        } catch {
          // Digest is best-effort for display; don't fail the bundle load on it.
        }
        if (cancelled) return;
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
    // The verdict is derived ONLY from authenticated state. The manifest is
    // the trust root; every eager artifact and every lazy artifact we render
    // is hash-checked against `manifest.sha256` before display. A FAIL here
    // means at least one such check failed.
    //
    // We deliberately do NOT factor in `bundle.review.ok` because
    // `review-result.json` is excluded from `manifest.sha256` by
    // `artifacts.py` (it is written after the manifest is sealed), so its
    // contents are unauthenticated and an attacker who can edit only that
    // file could otherwise flip the verdict. `review.ok` is surfaced as
    // advisory metadata elsewhere; it must not be load-bearing here.
    if (!bundle) return "PASS";
    return hashMismatch ? "FAIL" : "PASS";
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

export function useBundle(): BundleContextValue {
  const ctx = useContext(BundleContext);
  if (!ctx) {
    throw new Error("useBundle must be used within a BundleProvider");
  }
  return ctx;
}
