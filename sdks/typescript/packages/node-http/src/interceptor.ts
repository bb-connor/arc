/**
 * HTTP request interceptor -- the core interception substrate.
 *
 * Handles both Node.js (req, res) and Web API (Request -> Response) patterns.
 * Extracts caller identity, builds ArcHttpRequest, sends to sidecar,
 * and produces signed receipts.
 */

import { createHash, randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { defaultIdentityExtractor } from "./identity.js";
import { ArcSidecarClient, SidecarError } from "./sidecar-client.js";
import type {
  ArcConfig,
  ArcErrorResponse,
  ArcHttpRequest,
  CallerIdentity,
  EvaluateResponse,
  HttpMethod,
  IdentityExtractor,
  RoutePatternResolver,
  Verdict,
} from "./types.js";
import { ARC_ERROR_CODES, isDenied } from "./types.js";

// -- Helpers --

function sha256Hex(input: Uint8Array | string): string {
  return createHash("sha256").update(input).digest("hex");
}

function normalizeMethod(method: string): HttpMethod | null {
  const upper = method.toUpperCase();
  const valid: HttpMethod[] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
  return valid.includes(upper as HttpMethod) ? (upper as HttpMethod) : null;
}

function headersToRecord(headers: Record<string, string | string[] | undefined>): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (value != null) {
      result[key.toLowerCase()] = Array.isArray(value) ? value.join(", ") : value;
    }
  }
  return result;
}

function parseQueryString(url: string): Record<string, string> {
  const query: Record<string, string> = {};
  const qIndex = url.indexOf("?");
  if (qIndex === -1) return query;
  const qs = url.slice(qIndex + 1);
  for (const pair of qs.split("&")) {
    const eqIndex = pair.indexOf("=");
    if (eqIndex === -1) {
      query[decodeURIComponent(pair)] = "";
    } else {
      const key = decodeURIComponent(pair.slice(0, eqIndex));
      const value = decodeURIComponent(pair.slice(eqIndex + 1));
      query[key] = value;
    }
  }
  return query;
}

function extractPath(url: string): string {
  const qIndex = url.indexOf("?");
  return qIndex === -1 ? url : url.slice(0, qIndex);
}

/** Default route pattern resolver -- returns the raw path as pattern. */
const defaultRoutePatternResolver: RoutePatternResolver = (_method, path) => path;

// -- Resolved config with defaults applied --

export interface ResolvedConfig {
  sidecarUrl: string;
  identityExtractor: IdentityExtractor;
  routePatternResolver: RoutePatternResolver;
  onSidecarError: "deny" | "allow";
  timeoutMs: number;
  forwardHeaders: string[];
  client: ArcSidecarClient;
}

/** Resolve config defaults. */
export function resolveConfig(config: ArcConfig): ResolvedConfig {
  const client = new ArcSidecarClient(config);
  return {
    sidecarUrl: config.sidecarUrl ?? process.env["ARC_SIDECAR_URL"] ?? "http://127.0.0.1:9090",
    identityExtractor: config.identityExtractor ?? defaultIdentityExtractor,
    routePatternResolver: config.routePatternResolver ?? defaultRoutePatternResolver,
    onSidecarError: config.onSidecarError ?? "deny",
    timeoutMs: config.timeoutMs ?? 5000,
    forwardHeaders: config.forwardHeaders ?? ["content-type", "content-length", "x-arc-capability"],
    client,
  };
}

// -- Build ArcHttpRequest from Node.js IncomingMessage --

export interface BuildRequestOptions {
  method: HttpMethod;
  path: string;
  query: Record<string, string>;
  headers: Record<string, string>;
  caller: CallerIdentity;
  bodyHash: string | undefined;
  bodyLength: number;
  routePattern: string;
  capabilityId: string | undefined;
}

/** Build an ArcHttpRequest from extracted request parts. */
export function buildArcHttpRequest(opts: BuildRequestOptions): ArcHttpRequest {
  return {
    request_id: randomUUID(),
    method: opts.method,
    route_pattern: opts.routePattern,
    path: opts.path,
    query: opts.query,
    headers: filterHeaders(opts.headers, [
      "content-type",
      "content-length",
      "x-arc-capability",
    ]),
    caller: opts.caller,
    body_hash: opts.bodyHash,
    body_length: opts.bodyLength,
    session_id: undefined,
    capability_id: opts.capabilityId,
    timestamp: Math.floor(Date.now() / 1000),
  };
}

function filterHeaders(
  headers: Record<string, string>,
  allowed: string[],
): Record<string, string> {
  const result: Record<string, string> = {};
  const allowedSet = new Set(allowed.map((h) => h.toLowerCase()));
  for (const [key, value] of Object.entries(headers)) {
    if (allowedSet.has(key.toLowerCase())) {
      result[key] = value;
    }
  }
  return result;
}

// -- Node.js (req, res) interceptor --

/**
 * Intercept a Node.js (IncomingMessage, ServerResponse) pair.
 * Evaluates against the ARC sidecar and either allows the request
 * to proceed or sends a deny response.
 *
 * Returns the evaluation result if allowed, or null if denied (response already sent).
 */
export async function interceptNodeRequest(
  req: IncomingMessage,
  res: ServerResponse,
  resolved: ResolvedConfig,
): Promise<EvaluateResponse | null> {
  const method = normalizeMethod(req.method ?? "GET");
  if (method == null) {
    sendJsonResponse(res, 405, {
      error: ARC_ERROR_CODES.EVALUATION_FAILED,
      message: `unsupported HTTP method: ${req.method ?? "unknown"}`,
    });
    return null;
  }

  const url = req.url ?? "/";
  const path = extractPath(url);
  const query = parseQueryString(url);
  const rawHeaders = headersToRecord(req.headers as Record<string, string | string[] | undefined>);
  const caller = resolved.identityExtractor(req.headers as Record<string, string | string[] | undefined>);
  const routePattern = resolved.routePatternResolver(method, path);

  // Read body for hashing
  const bodyBytes = await readBody(req);
  const bodyHash = bodyBytes.length > 0 ? sha256Hex(bodyBytes) : undefined;
  const bodyLength = bodyBytes.length;

  const capabilityId = rawHeaders["x-arc-capability"] ?? undefined;

  const arcReq = buildArcHttpRequest({
    method,
    path,
    query,
    headers: rawHeaders,
    caller,
    bodyHash: bodyHash,
    bodyLength,
    routePattern,
    capabilityId,
  });

  try {
    const result = await resolved.client.evaluate(arcReq);

    // Attach receipt ID to response
    res.setHeader("X-Arc-Receipt-Id", result.receipt.id);

    if (isDenied(result.verdict)) {
      sendJsonResponse(res, result.verdict.http_status, {
        error: ARC_ERROR_CODES.ACCESS_DENIED,
        message: result.verdict.reason,
        receipt_id: result.receipt.id,
        suggestion: "provide a valid capability token in the X-Arc-Capability header",
      });
      return null;
    }

    return result;
  } catch (error) {
    return handleSidecarError(res, resolved, error);
  }
}

// -- Web API Request -> Response interceptor --

/**
 * Intercept a Web API Request.
 * Returns an EvaluateResponse on allow, or a structured error Response on deny.
 */
export async function interceptWebRequest(
  request: Request,
  resolved: ResolvedConfig,
): Promise<{ response: Response; result: EvaluateResponse | null }> {
  const url = new URL(request.url);
  const method = normalizeMethod(request.method);

  if (method == null) {
    return {
      response: jsonResponse(405, {
        error: ARC_ERROR_CODES.EVALUATION_FAILED,
        message: `unsupported HTTP method: ${request.method}`,
      }),
      result: null,
    };
  }

  const path = url.pathname;
  const query: Record<string, string> = {};
  url.searchParams.forEach((value, key) => {
    query[key] = value;
  });

  const rawHeaders: Record<string, string> = {};
  request.headers.forEach((value, key) => {
    rawHeaders[key.toLowerCase()] = value;
  });

  const headerObj: Record<string, string | string[] | undefined> = {};
  request.headers.forEach((value, key) => {
    headerObj[key] = value;
  });
  const caller = resolved.identityExtractor(headerObj);
  const routePattern = resolved.routePatternResolver(method, path);

  // Read body for hashing
  let bodyHash: string | undefined;
  let bodyLength = 0;
  if (request.body != null) {
    const bodyBytes = new Uint8Array(await request.arrayBuffer());
    bodyLength = bodyBytes.length;
    if (bodyLength > 0) {
      bodyHash = sha256Hex(bodyBytes);
    }
  }

  const capabilityId = rawHeaders["x-arc-capability"] ?? undefined;

  const arcReq = buildArcHttpRequest({
    method,
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
    const evalResult = await resolved.client.evaluate(arcReq);

    if (isDenied(evalResult.verdict)) {
      const resp = jsonResponse(evalResult.verdict.http_status, {
        error: ARC_ERROR_CODES.ACCESS_DENIED,
        message: evalResult.verdict.reason,
        receipt_id: evalResult.receipt.id,
        suggestion: "provide a valid capability token in the X-Arc-Capability header",
      });
      resp.headers.set("X-Arc-Receipt-Id", evalResult.receipt.id);
      return { response: resp, result: evalResult };
    }

    // Return a marker response that the framework wrapper will replace
    // with the actual upstream response.
    const resp = new Response(null, { status: 200 });
    resp.headers.set("X-Arc-Receipt-Id", evalResult.receipt.id);
    return { response: resp, result: evalResult };
  } catch (error) {
    if (resolved.onSidecarError === "allow") {
      return {
        response: new Response(null, { status: 200 }),
        result: null,
      };
    }
    const message =
      error instanceof SidecarError
        ? error.message
        : `sidecar error: ${error instanceof Error ? error.message : String(error)}`;

    return {
      response: jsonResponse(502, {
        error: ARC_ERROR_CODES.SIDECAR_UNREACHABLE,
        message,
      }),
      result: null,
    };
  }
}

// -- Helpers --

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function sendJsonResponse(res: ServerResponse, status: number, body: ArcErrorResponse): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

function jsonResponse(status: number, body: ArcErrorResponse): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function handleSidecarError(
  res: ServerResponse,
  resolved: ResolvedConfig,
  error: unknown,
): EvaluateResponse | null {
  if (resolved.onSidecarError === "allow") {
    return null;
  }

  const message =
    error instanceof SidecarError
      ? error.message
      : `sidecar error: ${error instanceof Error ? error.message : String(error)}`;

  sendJsonResponse(res, 502, {
    error: ARC_ERROR_CODES.SIDECAR_UNREACHABLE,
    message,
  });
  return null;
}
