/**
 * Elysia lifecycle hook for ARC protocol.
 *
 * Usage:
 *   import { Elysia } from "elysia";
 *   import { arc } from "@arc-protocol/elysia";
 *
 *   const app = new Elysia()
 *     .use(arc({ config: "arc.yaml" }))
 *     .get("/", () => "Hello");
 *
 * The plugin intercepts every request via Elysia's beforeHandle lifecycle,
 * evaluates it against the ARC sidecar kernel, and either allows it to
 * proceed or returns a structured error response with ARC error codes.
 */

import { Elysia } from "elysia";
import {
  type ArcConfig,
  type EvaluateResponse,
  type HttpMethod,
  ARC_ERROR_CODES,
  isDenied,
  resolveConfig,
  buildArcHttpRequest,
  interceptWebRequest,
} from "@arc-protocol/node-http";
import { createHash } from "node:crypto";

/** Elysia-specific ARC config. */
export interface ArcElysiaConfig extends ArcConfig {
  /**
   * Skip ARC evaluation for specific paths.
   * Accepts exact paths or RegExp patterns.
   */
  skip?: Array<string | RegExp> | undefined;
}

/** Valid HTTP methods for ARC evaluation. */
const VALID_METHODS = new Set<string>([
  "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
]);

/**
 * Create an Elysia plugin that evaluates every request against ARC.
 *
 * @example
 * ```ts
 * import { Elysia } from "elysia";
 * import { arc } from "@arc-protocol/elysia";
 *
 * const app = new Elysia()
 *   .use(arc({ config: "arc.yaml" }))
 *   .get("/pets", () => [{ name: "Fido" }]);
 * ```
 */
export function arc(config: ArcElysiaConfig = {}) {
  const resolved = resolveConfig(config);
  const skipPatterns = config.skip ?? [];

  return new Elysia({ name: "@arc-protocol/elysia" })
    .derive({ as: "global" }, ({ request }) => {
      // Store the ARC result on the context for downstream handlers
      return {
        arcResult: undefined as EvaluateResponse | undefined,
      };
    })
    .onBeforeHandle({ as: "global" }, async ({ request, set }) => {
      const url = new URL(request.url);
      const path = url.pathname;

      // Check skip patterns
      if (shouldSkip(path, skipPatterns)) {
        return undefined;
      }

      const method = request.method.toUpperCase();
      if (!VALID_METHODS.has(method)) {
        set.status = 405;
        return {
          error: ARC_ERROR_CODES.EVALUATION_FAILED,
          message: `unsupported HTTP method: ${method}`,
        };
      }

      const httpMethod = method as HttpMethod;

      // Extract headers
      const rawHeaders: Record<string, string> = {};
      const headerObj: Record<string, string | string[] | undefined> = {};
      request.headers.forEach((value, key) => {
        rawHeaders[key.toLowerCase()] = value;
        headerObj[key] = value;
      });

      // Extract caller identity
      const caller = resolved.identityExtractor(headerObj);
      const routePattern = resolved.routePatternResolver(httpMethod, path);

      // Parse query parameters
      const query: Record<string, string> = {};
      url.searchParams.forEach((value, key) => {
        query[key] = value;
      });

      // Compute body hash
      let bodyHash: string | undefined;
      let bodyLength = 0;
      if (request.body != null) {
        try {
          // Clone request to read the body without consuming it
          const cloned = request.clone();
          const bodyBytes = new Uint8Array(await cloned.arrayBuffer());
          bodyLength = bodyBytes.length;
          if (bodyLength > 0) {
            bodyHash = createHash("sha256").update(bodyBytes).digest("hex");
          }
        } catch {
          // Body may not be readable; continue without hash
        }
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

        // Set receipt header
        set.headers["X-Arc-Receipt-Id"] = result.receipt.id;

        if (isDenied(result.verdict)) {
          set.status = result.verdict.http_status;
          return {
            error: ARC_ERROR_CODES.ACCESS_DENIED,
            message: result.verdict.reason,
            receipt_id: result.receipt.id,
            suggestion: "provide a valid capability token in the X-Arc-Capability header or arc_capability query parameter",
          };
        }

        // Allow the request to proceed
        return undefined;
      } catch (error) {
        if (resolved.onSidecarError === "allow") {
          return undefined;
        }

        const message = error instanceof Error ? error.message : String(error);
        set.status = 502;
        return {
          error: ARC_ERROR_CODES.SIDECAR_UNREACHABLE,
          message,
        };
      }
    });
}

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
