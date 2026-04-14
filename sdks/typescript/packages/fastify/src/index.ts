/**
 * @arc-protocol/fastify
 *
 * Fastify plugin for the ARC protocol. Provides:
 *
 * - `arc` plugin that evaluates requests against the ARC sidecar
 * - ARC evaluation results attached to request.arcResult
 *
 * @example
 * ```ts
 * import Fastify from "fastify";
 * import { arc } from "@arc-protocol/fastify";
 *
 * const fastify = Fastify();
 * fastify.register(arc, { config: "arc.yaml" });
 * ```
 */

export { arc, type ArcFastifyConfig } from "./plugin.js";

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
