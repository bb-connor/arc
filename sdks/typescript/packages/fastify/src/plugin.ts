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
  ARC_ERROR_CODES,
  isDenied,
  resolveConfig,
  buildArcHttpRequest,
} from "@arc-protocol/node-http";
import { createHash } from "node:crypto";
import { PassThrough } from "node:stream";

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
    arcRawBody?: Buffer | undefined;
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
  fastify.decorateRequest("arcRawBody", undefined);

  fastify.addHook("preParsing", async (request, _reply, payload) => {
    const chunks: Buffer[] = [];
    for await (const chunk of payload) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }

    const bodyBytes = Buffer.concat(chunks);
    request.arcRawBody = bodyBytes;

    const replay = new PassThrough();
    replay.end(bodyBytes);
    (replay as PassThrough & { receivedEncodedLength?: number }).receivedEncodedLength =
      bodyBytes.length;
    return replay;
  });

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

    // Compute body hash from the raw request bytes captured in preParsing.
    let bodyHash: string | undefined;
    let bodyLength = 0;
    const rawBody = request.arcRawBody;
    if (rawBody != null && rawBody.length > 0) {
      bodyLength = rawBody.length;
      bodyHash = createHash("sha256").update(rawBody).digest("hex");
    }

    const capabilityToken = rawHeaders["x-arc-capability"] ?? query["arc_capability"] ?? undefined;
    let capabilityId: string | undefined;
    if (capabilityToken != null) {
      try {
        const parsed = JSON.parse(capabilityToken) as { id?: unknown };
        capabilityId = typeof parsed.id === "string" ? parsed.id : undefined;
      } catch {
        capabilityId = undefined;
      }
    }

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
      const result = await resolved.client.evaluate(arcReq, rawHeaders["x-arc-capability"] ?? undefined);

      // Attach receipt ID header
      reply.header("X-Arc-Receipt-Id", result.receipt.id);

      if (isDenied(result.verdict)) {
        reply.code(result.verdict.http_status).send({
          error: ARC_ERROR_CODES.ACCESS_DENIED,
          message: result.verdict.reason,
          receipt_id: result.receipt.id,
          suggestion: "provide a valid capability token in the X-Arc-Capability header or arc_capability query parameter",
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
