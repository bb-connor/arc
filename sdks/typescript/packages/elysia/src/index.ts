/**
 * @chio-protocol/elysia
 *
 * Elysia lifecycle hook for the Chio protocol. Provides:
 *
 * - `chio()` plugin that evaluates requests against the Chio sidecar
 * - Structured Chio error responses
 *
 * @example
 * ```ts
 * import { Elysia } from "elysia";
 * import { chio } from "@chio-protocol/elysia";
 *
 * const app = new Elysia()
 *   .use(chio({ config: "chio.yaml" }))
 *   .get("/", () => "Hello");
 * ```
 */

export { chio, type ChioElysiaConfig } from "./plugin.js";

// Re-export key types from node-http for convenience
export type {
  ChioConfig,
  EvaluateResponse,
  HttpReceipt,
  Verdict,
  CallerIdentity,
  GuardEvidence,
  ChioErrorResponse,
} from "@chio-protocol/node-http";
