/**
 * @arc-protocol/express
 *
 * Express middleware for the ARC protocol. Provides:
 *
 * - `arc()` middleware that evaluates requests against the ARC sidecar
 * - `arcErrorHandler` for structured ARC error responses
 * - ARC evaluation results attached to req.arcResult
 *
 * @example
 * ```ts
 * import express from "express";
 * import { arc, arcErrorHandler } from "@arc-protocol/express";
 *
 * const app = express();
 * app.use(arc({ config: "arc.yaml" }));
 * app.use(arcErrorHandler);
 * ```
 */

export { arc, arcErrorHandler, type ArcExpressConfig, type ArcRequest } from "./middleware.js";

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
