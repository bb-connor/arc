/**
 * @arc-protocol/elysia
 *
 * Elysia lifecycle hook for the ARC protocol. Provides:
 *
 * - `arc()` plugin that evaluates requests against the ARC sidecar
 * - Structured ARC error responses
 *
 * @example
 * ```ts
 * import { Elysia } from "elysia";
 * import { arc } from "@arc-protocol/elysia";
 *
 * const app = new Elysia()
 *   .use(arc({ config: "arc.yaml" }))
 *   .get("/", () => "Hello");
 * ```
 */

export { arc, type ArcElysiaConfig } from "./plugin.js";

// Re-export key types from node-http for convenience
export type {
  ArcConfig,
  EvaluateResponse,
  HttpReceipt,
  Verdict,
  CallerIdentity,
  GuardEvidence,
  ArcErrorResponse,
} from "@arc-protocol/node-http";
