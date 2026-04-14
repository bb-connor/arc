/**
 * Fastify plugin for ARC protocol.
 *
 * Usage:
 *   import Fastify from "fastify";
 *   import { arc } from "@arc-protocol/fastify";
 *
 *   const fastify = Fastify();
 *   fastify.register(arc, { config: "arc.yaml" });
 *
 * The plugin intercepts every request via an onRequest hook, evaluates it
 * against the ARC sidecar kernel, and either allows it to proceed or
 * returns a structured error response with ARC error codes.
 */

import type {
  FastifyInstance,
  FastifyPluginAsync,
  FastifyRequest,
  FastifyReply,
} from "fastify";
import fp from "fastify-plugin";
import {
  type ArcConfig,
  type EvaluateResponse,
  type HttpMethod,
  type ArcHttpRequest,
  type CallerIdentity,
  ARC_ERROR_CODES,
  isDenied,
  resolveConfig,
  type ResolvedConfig,
  buildArcHttpRequest,
} from "@arc-protocol/node-http";
import { createHash, randomUUID } from "node:crypto";

/** Fastify-specific ARC config. */
export interface ArcFastifyConfig extends ArcConfig {
  /**
   * Skip ARC evaluation for specific paths.
   * Accepts exact paths or RegExp patterns.
   */
  skip?: Array<string | RegExp> | undefined;
}

/** Augment FastifyRequest to carry ARC evaluation result. */
declare module "fastify" {
  interface FastifyRequest {
    arcResult?: EvaluateResponse | undefined;
  }
}

/** Valid HTTP methods for ARC evaluation. */
const VALID_METHODS = new Set<string>([
  "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
]);

/**
 * Internal plugin implementation (before wrapping with fastify-plugin).
 */
const arcPlugin: FastifyPluginAsync<ArcFastifyConfig> = async (
  fastify: FastifyInstance,
  opts: ArcFastifyConfig,
): Promise<void> => {
  const resolved = resolveConfig(opts);
  const skipPatterns = opts.skip ?? [];

  // Decorate request with arcResult
  fastify.decorateRequest("arcResult", undefined);

  // Register preHandler hook (runs after parsing, before the handler)
  fastify.addHook("preHandler", async (request: FastifyRequest, reply: FastifyReply) => {
    // Check skip patterns
    const path = request.url.split("?")[0] ?? request.url;
    if (shouldSkip(path, skipPatterns)) {
      return;
    }

    const method = request.method.toUpperCase();
    if (!VALID_METHODS.has(method)) {
      reply.code(405).send({
        error: ARC_ERROR_CODES.EVALUATION_FAILED,
        message: `unsupported HTTP method: ${method}`,
      });
      return reply;
    }

    const httpMethod = method as HttpMethod;

    // Extract headers
    const rawHeaders: Record<string, string> = {};
    const headerObj: Record<string, string | string[] | undefined> = {};
    for (const [key, value] of Object.entries(request.headers)) {
      if (value != null) {
        rawHeaders[key.toLowerCase()] = Array.isArray(value) ? value.join(", ") : value;
        headerObj[key] = value;
      }
    }

    // Extract caller identity
    const caller = resolved.identityExtractor(headerObj);

    // Get route pattern from Fastify's router
    const routePattern = extractRoutePattern(request, path);

    // Parse query parameters
    const query: Record<string, string> = {};
    const qIndex = request.url.indexOf("?");
    if (qIndex !== -1) {
      const qs = request.url.slice(qIndex + 1);
      for (const pair of qs.split("&")) {
        const eqIndex = pair.indexOf("=");
        if (eqIndex === -1) {
          query[decodeURIComponent(pair)] = "";
        } else {
          query[decodeURIComponent(pair.slice(0, eqIndex))] =
            decodeURIComponent(pair.slice(eqIndex + 1));
        }
      }
    }

    // Compute body hash (Fastify may have already parsed the body)
    let bodyHash: string | undefined;
    let bodyLength = 0;
    const rawBody = request.body;
    if (rawBody != null) {
      let bodyBytes: Buffer;
      if (Buffer.isBuffer(rawBody)) {
        bodyBytes = rawBody;
      } else if (typeof rawBody === "string") {
        bodyBytes = Buffer.from(rawBody, "utf-8");
      } else {
        bodyBytes = Buffer.from(JSON.stringify(rawBody), "utf-8");
      }
      bodyLength = bodyBytes.length;
      if (bodyLength > 0) {
        bodyHash = createHash("sha256").update(bodyBytes).digest("hex");
      }
    }

    const capabilityId = rawHeaders["x-arc-capability"] ?? undefined;

    const arcReq = buildArcHttpRequest({
      method: httpMethod,
      path,
      query,
      headers: rawHeaders,
      caller,
      bodyHash,
      bodyLength,
      routePattern,
      capabilityId,
    });

    try {
      const result = await resolved.client.evaluate(arcReq);

      // Attach receipt ID header
      reply.header("X-Arc-Receipt-Id", result.receipt.id);

      if (isDenied(result.verdict)) {
        reply.code(result.verdict.http_status).send({
          error: ARC_ERROR_CODES.ACCESS_DENIED,
          message: result.verdict.reason,
          receipt_id: result.receipt.id,
          suggestion: "provide a valid capability token in the X-Arc-Capability header",
        });
        return reply;
      }

      // Attach result for downstream handlers
      request.arcResult = result;
    } catch (error) {
      if (resolved.onSidecarError === "allow") {
        return;
      }

      const message = error instanceof Error ? error.message : String(error);
      reply.code(502).send({
        error: ARC_ERROR_CODES.SIDECAR_UNREACHABLE,
        message,
      });
      return reply;
    }
  });
};

/**
 * Fastify plugin that evaluates every request against ARC.
 * Wrapped with fastify-plugin to skip encapsulation, so hooks apply
 * to all routes in the Fastify instance.
 */
export const arc = fp(arcPlugin, {
  name: "@arc-protocol/fastify",
  fastify: ">=4.0.0",
});

// -- Helpers --

function shouldSkip(path: string, patterns: Array<string | RegExp>): boolean {
  for (const pattern of patterns) {
    if (typeof pattern === "string") {
      if (path === pattern) return true;
    } else {
      if (pattern.test(path)) return true;
    }
  }
  return false;
}

function extractRoutePattern(request: FastifyRequest, fallbackPath: string): string {
  // Fastify provides routeOptions.url which is the route pattern
  if (request.routeOptions != null && typeof request.routeOptions.url === "string") {
    return request.routeOptions.url;
  }
  return fallbackPath;
}
