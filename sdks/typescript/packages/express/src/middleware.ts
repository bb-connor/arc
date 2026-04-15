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
import { PassThrough } from "node:stream";
import {
  type ArcConfig,
  type ArcPassthrough,
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
        const rawBody = await ensureExpressBufferedBody(req as ArcRequest);
        const outcome = await interceptNodeRequest(req, res, resolved);
        if (!outcome.responseSent) {
          hydrateExpressBody(req as ArcRequest, rawBody);
          if (outcome.result != null) {
            (req as ArcRequest).arcResult = outcome.result;
          }
          if (outcome.passthrough != null) {
            (req as ArcRequest).arcPassthrough = outcome.passthrough;
          }
          next();
        }
      } catch (error) {
        next(error);
      } finally {
        resolved.routePatternResolver = saved;
      }
      return;
    }

    try {
      const rawBody = await ensureExpressBufferedBody(req as ArcRequest);
      const outcome = await interceptNodeRequest(req, res, resolved);
      if (!outcome.responseSent) {
        hydrateExpressBody(req as ArcRequest, rawBody);
        if (outcome.result != null) {
          (req as ArcRequest).arcResult = outcome.result;
        }
        if (outcome.passthrough != null) {
          (req as ArcRequest).arcPassthrough = outcome.passthrough;
        }
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
  arcPassthrough?: ArcPassthrough | undefined;
  rawBody?: Buffer | undefined;
  _body?: boolean | undefined;
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

async function ensureExpressBufferedBody(req: ArcRequest): Promise<Buffer> {
  if (Buffer.isBuffer(req.rawBody)) {
    return req.rawBody;
  }

  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  const rawBody = Buffer.concat(chunks);
  req.rawBody = rawBody;
  replayExpressRequestBody(req, rawBody);
  return rawBody;
}

function replayExpressRequestBody(req: ArcRequest, rawBody: Buffer): void {
  const replay = new PassThrough();
  replay.end(rawBody);

  const replayable = req as unknown as Record<string | symbol, unknown>;
  const methods = [
    "on",
    "once",
    "addListener",
    "prependListener",
    "prependOnceListener",
    "removeListener",
    "off",
    "pipe",
    "unpipe",
    "pause",
    "resume",
    "read",
    "setEncoding",
  ] as const;

  for (const method of methods) {
    const impl = replay[method];
    if (typeof impl === "function") {
      replayable[method] = impl.bind(replay) as unknown;
    }
  }

  Object.defineProperty(replayable, "_readableState", {
    configurable: true,
    enumerable: false,
    get: () => (replay as PassThrough & { _readableState: unknown })._readableState,
  });

  Object.defineProperty(replayable, "complete", {
    configurable: true,
    enumerable: false,
    get: () => replay.readableEnded,
  });

  for (const property of [
    "readable",
    "readableEnded",
    "readableEncoding",
    "readableFlowing",
    "readableLength",
  ] as const) {
    Object.defineProperty(replayable, property, {
      configurable: true,
      enumerable: false,
      get: () => replay[property],
    });
  }
}

function hydrateExpressBody(req: ArcRequest, rawBody: Buffer): void {
  if (req.body !== undefined) {
    return;
  }

  const contentTypeHeader = req.headers["content-type"];
  const contentType = Array.isArray(contentTypeHeader)
    ? contentTypeHeader[0]
    : contentTypeHeader;
  const normalizedType = contentType?.split(";")[0]?.trim().toLowerCase();

  try {
    if (normalizedType === "application/json" || normalizedType?.endsWith("+json") === true) {
      req.body = rawBody.length > 0 ? JSON.parse(rawBody.toString("utf-8")) : {};
      req._body = true;
      return;
    }

    if (normalizedType === "application/x-www-form-urlencoded") {
      req.body = Object.fromEntries(
        new URLSearchParams(rawBody.toString("utf-8")).entries(),
      );
      req._body = true;
      return;
    }

    if (normalizedType?.startsWith("text/") === true) {
      req.body = rawBody.toString("utf-8");
      req._body = true;
      return;
    }

    if (rawBody.length > 0) {
      req.body = rawBody;
      req._body = true;
    }
  } catch {
    // Leave body parsing to downstream middleware when ARC cannot safely infer it.
  }
}
