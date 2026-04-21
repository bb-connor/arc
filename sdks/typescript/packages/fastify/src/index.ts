/**
 * @chio-protocol/fastify
 *
 * Fastify plugin for the Chio protocol. Provides:
 *
 * - `arc` plugin that evaluates requests against the Chio sidecar
 * - Chio evaluation results attached to request.chioResult
 *
 * @example
 * ```ts
 * import Fastify from "fastify";
 * import { chio } from "@chio-protocol/fastify";
 *
 * const fastify = Fastify();
 * fastify.register(arc, { config: "chio.yaml" });
 * ```
 */

export { chio, type ChioFastifyConfig } from "./plugin.js";

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
