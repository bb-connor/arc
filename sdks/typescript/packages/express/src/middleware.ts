/**
 * Express middleware for ARC protocol.
 *
 * Usage:
 *   import { arc } from "@arc-protocol/express";
 *   app.use(arc({ config: "arc.yaml" }));
 *
 * The middleware intercepts every request, evaluates it against the ARC
 * sidecar kernel, and either allows it to proceed or returns a structured
 * error response with ARC error codes.
 */

import type { Request, Response, NextFunction, RequestHandler } from "express";
import {
  type ArcConfig,
  type EvaluateResponse,
  type HttpMethod,
  type Verdict,
  ARC_ERROR_CODES,
  isDenied,
  resolveConfig,
  type ResolvedConfig,
  interceptNodeRequest,
} from "@arc-protocol/node-http";

/** Express-specific ARC config with route pattern extraction. */
export interface ArcExpressConfig extends ArcConfig {
  /**
   * Skip ARC evaluation for specific paths.
   * Accepts exact paths or RegExp patterns.
   */
  skip?: Array<string | RegExp> | undefined;
}

/**
 * Create an Express middleware that evaluates every request against ARC.
 *
 * @example
 * ```ts
 * import express from "express";
 * import { arc } from "@arc-protocol/express";
 *
 * const app = express();
 * app.use(arc({ config: "arc.yaml" }));
 * ```
 */
export function arc(config: ArcExpressConfig = {}): RequestHandler {
  const resolved = resolveConfig(config);
  const skipPatterns = config.skip ?? [];

  // Override route pattern resolver to use Express route information
  const originalResolver = resolved.routePatternResolver;
  resolved.routePatternResolver = (method: HttpMethod, path: string): string => {
    // Express populates req.route after matching. Since we run as
    // middleware before the route handler, we fall back to the raw path.
    // Framework-level route pattern is injected in the middleware below.
    return originalResolver(method, path);
  };

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    // Check skip patterns
    if (shouldSkip(req.path, skipPatterns)) {
      next();
      return;
    }

    // Use Express route pattern if available
    const routePattern = extractRoutePattern(req);
    if (routePattern != null) {
      const saved = resolved.routePatternResolver;
      resolved.routePatternResolver = () => routePattern;

      try {
        const result = await interceptNodeRequest(req, res, resolved);
        if (result != null) {
          // Attach result to request for downstream handlers
          (req as ArcRequest).arcResult = result;
          next();
        }
        // If result is null, interceptor already sent the response
      } catch (error) {
        next(error);
      } finally {
        resolved.routePatternResolver = saved;
      }
      return;
    }

    try {
      const result = await interceptNodeRequest(req, res, resolved);
      if (result != null) {
        (req as ArcRequest).arcResult = result;
        next();
      }
    } catch (error) {
      next(error);
    }
  };
}

/**
 * Express request with ARC evaluation result attached.
 */
export interface ArcRequest extends Request {
  arcResult?: EvaluateResponse | undefined;
}

/**
 * Express error handler that formats ARC errors as structured JSON.
 */
export function arcErrorHandler(
  err: Error,
  _req: Request,
  res: Response,
  next: NextFunction,
): void {
  if (res.headersSent) {
    next(err);
    return;
  }

  // Check if this is an ARC-related error
  if ("code" in err && typeof (err as { code: unknown }).code === "string") {
    const code = (err as { code: string }).code;
    if (code.startsWith("arc_")) {
      res.status(502).json({
        error: code,
        message: err.message,
      });
      return;
    }
  }

  next(err);
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

function extractRoutePattern(req: Request): string | null {
  // Express 4/5 populates req.route after matching.
  // In middleware that runs before route matching, this is not available.
  // We try req.route.path first, then fall back.
  if (req.route != null && typeof req.route.path === "string") {
    // Combine with baseUrl for mounted routers
    const base = req.baseUrl ?? "";
    return `${base}${req.route.path}`;
  }
  return null;
}
