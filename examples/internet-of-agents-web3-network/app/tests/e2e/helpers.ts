// Small Playwright e2e helpers.
//
// - waitForHealth polls /api/health until it returns { ok: true } or the
//   timeout elapses. It throws on timeout so test setup fails closed.
// - spawnNextServer launches a `bun run start` child process against a
//   specific bundle directory and port, returning a cleanup callback.

import { spawn, type ChildProcess } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

export async function waitForHealth(baseUrl: string, timeoutMs = 60_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  const target = `${baseUrl.replace(/\/$/, "")}/api/health`;
  let lastError: unknown = null;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(target, { cache: "no-store" });
      // /api/health returns 200 on ok, 500 with JSON body otherwise.
      // For the "good" case we require 200. For the empty-bundle case the
      // caller should expect non-200 but we still want to confirm the
      // server is up, so we accept any successful HTTP response that
      // includes a JSON body.
      const body = (await res.json().catch(() => null)) as { ok?: boolean } | null;
      if (res.status === 200 && body && body.ok === true) {
        return;
      }
      if (body !== null) {
        // Server is responding but reporting an env error. Still "up".
        return;
      }
    } catch (err) {
      lastError = err;
    }
    await sleep(250);
  }
  const suffix = lastError instanceof Error ? `: ${lastError.message}` : "";
  throw new Error(`Timed out waiting for ${target}${suffix}`);
}

export interface SpawnNextOpts {
  port: number;
  bundleDir: string;
  cwd: string;
  env?: NodeJS.ProcessEnv;
}

export interface SpawnedServer {
  baseUrl: string;
  child: ChildProcess;
  cleanup: () => Promise<void>;
}

export async function spawnNextServer(opts: SpawnNextOpts): Promise<SpawnedServer> {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ...(opts.env ?? {}),
    CHIO_BUNDLE_DIR: opts.bundleDir,
    PORT: String(opts.port),
  };
  const child = spawn("bun", ["run", "start"], {
    cwd: opts.cwd,
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });

  const baseUrl = `http://127.0.0.1:${opts.port}`;
  const cleanup = async (): Promise<void> => {
    if (child.exitCode !== null || child.killed) return;
    try {
      child.kill("SIGTERM");
    } catch {
      // ignore
    }
    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        try {
          child.kill("SIGKILL");
        } catch {
          // ignore
        }
        resolve();
      }, 4000);
      child.once("exit", () => {
        clearTimeout(timer);
        resolve();
      });
    });
  };

  try {
    await waitForHealth(baseUrl, 60_000);
  } catch (err) {
    await cleanup();
    throw err;
  }

  return { baseUrl, child, cleanup };
}
