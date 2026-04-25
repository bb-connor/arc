// Streams JSON files out of the artifact-dir specified by CHIO_BUNDLE_DIR.
//
// Path-traversal guard: the resolved on-disk path must remain a subpath of the
// bundle dir, including after following symlinks via fs.realpath. Null bytes
// in the joined path are rejected with a generic 400 (no echo of the input).
// Only .json files are served.

import { NextResponse } from "next/server";
import path from "node:path";
import fs from "node:fs/promises";

import { EnvError, readServerEnv } from "@/lib/env";

export const dynamic = "force-dynamic";

interface RouteContext {
  params: Promise<{ path?: string[] }>;
}

function jsonError(status: number, message: string, bodyExtras: Record<string, unknown> = {}): NextResponse {
  return NextResponse.json({ error: message, ...bodyExtras }, { status });
}

// Cache the resolved real-path of the bundle dir so we don't pay a realpath
// syscall on every request.
let cachedBundleDir: string | null = null;
let cachedBundleDirReal: string | null = null;

async function resolveBundleRoots(bundleDir: string): Promise<{ abs: string; real: string }> {
  const abs = path.resolve(bundleDir);
  if (cachedBundleDir === abs && cachedBundleDirReal) {
    return { abs, real: cachedBundleDirReal };
  }
  const real = await fs.realpath(abs);
  cachedBundleDir = abs;
  cachedBundleDirReal = real;
  return { abs, real };
}

function isWithin(root: string, target: string): boolean {
  const rel = path.relative(root, target);
  return !rel.startsWith("..") && !path.isAbsolute(rel);
}

export async function GET(_req: Request, context: RouteContext): Promise<NextResponse> {
  let env;
  try {
    env = readServerEnv();
  } catch (err) {
    if (err instanceof EnvError) {
      return jsonError(500, err.message, { reason: "env" });
    }
    return jsonError(500, "Unknown env error", { reason: "env" });
  }

  const params = await context.params;
  const segments = params.path ?? [];
  if (segments.length === 0) {
    return jsonError(400, "Path is required.");
  }
  const rel = segments.join("/");
  if (rel.includes("\x00")) {
    // Intentionally generic; do not echo the raw path.
    return jsonError(400, "Invalid path encoding.");
  }
  if (!rel.endsWith(".json")) {
    return jsonError(400, "Only .json artifacts are served.", { path: rel });
  }

  let rootAbs: string;
  let rootReal: string;
  try {
    const roots = await resolveBundleRoots(env.bundleDir);
    rootAbs = roots.abs;
    rootReal = roots.real;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    return jsonError(500, "Bundle root is not readable.", { code: code ?? "UNKNOWN" });
  }
  const targetAbs = path.resolve(rootAbs, rel);
  // First guard: the lexical resolve must remain inside the bundle root.
  if (!isWithin(rootAbs, targetAbs)) {
    return jsonError(400, "Path traversal is not allowed.", { path: rel });
  }

  let targetForRead = targetAbs;
  try {
    const realTarget = await fs.realpath(targetAbs);
    // Second guard: the realpath-resolved target must remain inside the
    // realpath-resolved root. Catches symlink escapes.
    if (!isWithin(rootReal, realTarget)) {
      return jsonError(400, "Path traversal is not allowed.", { path: rel });
    }
    targetForRead = realTarget;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === "ENOENT") {
      return jsonError(404, "Artifact not found in bundle.", { path: rel });
    }
    // Any other realpath error is a hard failure.
    return jsonError(500, "Failed to resolve artifact.", { path: rel, code: code ?? "UNKNOWN" });
  }

  try {
    const body = await fs.readFile(targetForRead);
    return new NextResponse(body, {
      status: 200,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
      },
    });
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === "ENOENT") {
      return jsonError(404, "Artifact not found in bundle.", { path: rel });
    }
    return jsonError(500, "Failed to read artifact.", {
      path: rel,
      code: code ?? "UNKNOWN",
    });
  }
}
