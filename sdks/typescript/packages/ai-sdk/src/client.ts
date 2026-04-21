/**
 * Minimal HTTP client for the Chio sidecar's tool-call evaluation endpoint.
 *
 * The sidecar exposes `POST /chio/evaluate` which accepts an `ChioHttpRequest`
 * payload. For AI SDK tool calls, this client builds a synthetic HTTP request
 * envelope that carries the tool identity plus arguments while remaining
 * decodable by the sidecar's HTTP substrate. It also normalizes both the
 * canonical `EvaluateResponse { verdict, receipt, evidence }` shape and the
 * older Lambda evaluator's flatter `{ receipt_id, decision }` shape to a
 * stable `ChioReceipt` API, while staying deliberately small so the Vercel AI
 * SDK wrapper does not pull in the full HTTP-substrate package.
 *
 * Transport uses `globalThis.fetch` (Node >= 20 ships it natively) and
 * supports a pluggable `fetch` override for testing.
 */

import { createHash, randomUUID } from "node:crypto";

/** Canonical decision verdict values returned by the sidecar. */
export type ChioVerdict = "allow" | "deny" | "cancel" | "incomplete";

/** Decision payload embedded in a receipt. */
export interface ChioDecision {
  verdict: ChioVerdict;
  /** Guard name on deny/cancel/incomplete verdicts. */
  guard?: string | undefined;
  /** Human-readable reason on deny/cancel/incomplete verdicts. */
  reason?: string | undefined;
}

/** Minimal shape of a sidecar-issued receipt we care about. */
export interface ChioReceipt {
  id: string;
  decision: ChioDecision;
  // Additional fields (tool_server, tool_name, signature, ...) are ignored
  // by this client but preserved on the wire for higher-level consumers.
  [key: string]: unknown;
}

/** Body of a tool-call evaluation request. */
export interface ChioEvaluateToolCallRequest {
  capability_id?: string | undefined;
  tool_server: string;
  tool_name: string;
  arguments?: unknown;
  parameters?: unknown;
  capability?: unknown;
  model_metadata?:
    | {
      model_id: string;
      safety_tier?: "low" | "standard" | "high" | "restricted" | undefined;
      provider?: string | undefined;
    }
    | undefined;
  /** Optional compatibility metadata forwarded alongside the evaluation payload. */
  metadata?: Record<string, unknown> | undefined;
}

interface ChioCallerIdentity {
  subject: string;
  auth_method: { method: "anonymous" };
  verified: boolean;
  tenant?: string | undefined;
  agent_id?: string | undefined;
}

interface ChioSidecarEvaluateRequest extends ChioEvaluateToolCallRequest {
  request_id: string;
  method: "POST";
  route_pattern: string;
  path: string;
  query: Record<string, string>;
  headers: Record<string, string>;
  caller: ChioCallerIdentity;
  body_hash?: string | undefined;
  body_length: number;
  session_id?: string | undefined;
  model_metadata?:
    | {
      model_id: string;
      safety_tier?: "low" | "standard" | "high" | "restricted" | undefined;
      provider?: string | undefined;
    }
    | undefined;
  timestamp: number;
}

/** Options accepted by the `ChioClient` constructor. */
export interface ChioClientOptions {
  /**
   * Base URL of the Chio sidecar (e.g. `"http://127.0.0.1:9090"`).
   * Defaults to `CHIO_SIDECAR_URL` env var or `"http://127.0.0.1:9090"`.
   */
  sidecarUrl?: string | undefined;
  /** Per-request timeout in milliseconds. Default `5000`. */
  timeoutMs?: number | undefined;
  /**
   * Pluggable fetch implementation. Defaults to `globalThis.fetch`. Exposed
   * primarily for unit testing without mocking globals.
   */
  fetch?: typeof fetch | undefined;
  /**
   * Optional debug hook. When provided, the client emits opaque trace
   * messages that tests or application wiring may surface. The wrapper never
   * writes to `console` directly.
   */
  debug?: ((message: string, data?: unknown) => void) | undefined;
}

/** Resolve the sidecar URL from explicit config or environment. */
export function resolveSidecarUrl(sidecarUrl: string | undefined): string {
  if (sidecarUrl != null && sidecarUrl.length > 0) {
    return sidecarUrl.replace(/\/+$/, "");
  }
  const envUrl = process.env["CHIO_SIDECAR_URL"];
  if (envUrl != null && envUrl.length > 0) {
    return envUrl.replace(/\/+$/, "");
  }
  return "http://127.0.0.1:9090";
}

/** Transport/protocol error emitted by the Chio client. */
export class ChioClientError extends Error {
  readonly code: string;
  readonly statusCode: number | undefined;

  constructor(code: string, message: string, statusCode?: number) {
    super(message);
    this.name = "ChioClientError";
    this.code = code;
    this.statusCode = statusCode;
  }
}

/**
 * Minimal client targeting `POST /chio/evaluate` on the Chio sidecar.
 *
 * Intentionally distinct from `@chio-protocol/node-http`'s HTTP-substrate
 * client, which evaluates inbound HTTP requests rather than outbound tool
 * calls. Consumers who need the HTTP substrate should import that package
 * directly; this client is scoped to the Vercel AI SDK tool-call shape.
 */
export class ChioClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly debug: ((message: string, data?: unknown) => void) | undefined;

  constructor(options: ChioClientOptions = {}) {
    this.baseUrl = resolveSidecarUrl(options.sidecarUrl);
    this.timeoutMs = options.timeoutMs ?? 5000;
    const fetchImpl = options.fetch ?? globalThis.fetch;
    if (fetchImpl == null) {
      throw new ChioClientError(
        "chio_fetch_unavailable",
        "no `fetch` implementation available; pass one via `ChioClientOptions.fetch`",
      );
    }
    this.fetchImpl = fetchImpl;
    this.debug = options.debug;
  }

  /** Resolved base URL (useful for diagnostics). */
  get sidecarUrl(): string {
    return this.baseUrl;
  }

  /**
   * Evaluate a tool call through the sidecar kernel. Returns the full
   * signed receipt. Throws `ChioClientError` on transport failures; the
   * `decision.verdict` on a returned receipt may still be `"deny"`.
   */
  async evaluateToolCall(
    body: ChioEvaluateToolCallRequest,
    options: { capabilityToken?: string | undefined } = {},
  ): Promise<ChioReceipt> {
    const url = `${this.baseUrl}/chio/evaluate`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    const headers: Record<string, string> = {
      "content-type": "application/json",
      accept: "application/json",
    };
    const normalizedBody: ChioEvaluateToolCallRequest = {
      ...body,
      arguments: body.arguments ?? body.parameters ?? null,
    };
    if (options.capabilityToken != null && options.capabilityToken.length > 0) {
      headers["x-chio-capability"] = options.capabilityToken;
      const capability = parseCapabilityToken(options.capabilityToken);
      normalizedBody.capability = normalizedBody.capability ?? capability;
      if ((normalizedBody.capability_id == null || normalizedBody.capability_id.length === 0)
        && typeof capability.id === "string"
        && capability.id.length > 0) {
        normalizedBody.capability_id = capability.id;
      }
    }
    const sidecarBody = buildSidecarRequest(normalizedBody);

    this.debug?.("chio.evaluate.request", {
      url,
      tool_server: sidecarBody.tool_server,
      tool_name: sidecarBody.tool_name,
      route_pattern: sidecarBody.route_pattern,
    });

    try {
      const response = await this.fetchImpl(url, {
        method: "POST",
        headers,
        body: JSON.stringify(sidecarBody),
        signal: controller.signal,
      });

      if (!response.ok) {
        const text = await response.text().catch(() => "");
        throw new ChioClientError(
          "chio_evaluation_failed",
          `sidecar returned ${response.status}: ${text}`,
          response.status,
        );
      }

      const receipt = normalizeReceipt(await response.json());
      if (receipt == null || typeof receipt !== "object" || receipt.decision == null) {
        throw new ChioClientError(
          "chio_invalid_receipt",
          "sidecar response missing `decision` field",
        );
      }
      this.debug?.("chio.evaluate.response", {
        id: receipt.id,
        verdict: receipt.decision.verdict,
      });
      return receipt;
    } catch (error) {
      if (error instanceof ChioClientError) {
        throw error;
      }
      if (error instanceof DOMException && error.name === "AbortError") {
        throw new ChioClientError(
          "chio_timeout",
          `sidecar request timed out after ${this.timeoutMs}ms`,
        );
      }
      const message = error instanceof Error ? error.message : String(error);
      throw new ChioClientError(
        "chio_sidecar_unreachable",
        `failed to reach sidecar at ${this.baseUrl}: ${message}`,
      );
    } finally {
      clearTimeout(timer);
    }
  }
}

function parseCapabilityToken(capabilityToken: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(capabilityToken) as Record<string, unknown>;
    if (parsed == null || typeof parsed !== "object") {
      throw new Error("capability token JSON must decode to an object");
    }
    return parsed;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new ChioClientError(
      "chio_invalid_capability",
      `failed to parse capability token JSON: ${message}`,
    );
  }
}

function buildSidecarRequest(body: ChioEvaluateToolCallRequest): ChioSidecarEvaluateRequest {
  const argumentsJson = JSON.stringify(body.arguments ?? null);
  const argumentsBytes = new TextEncoder().encode(argumentsJson);
  const toolPath = buildToolPath(body.tool_server, body.tool_name);
  const requestHeaders: Record<string, string> = {
    "content-type": "application/json",
    "content-length": String(argumentsBytes.byteLength),
  };

  return {
    ...body,
    request_id: randomUUID(),
    method: "POST",
    route_pattern: toolPath,
    path: toolPath,
    query: {},
    headers: requestHeaders,
    caller: anonymousCallerIdentity(),
    body_hash: sha256Hex(argumentsBytes),
    body_length: argumentsBytes.byteLength,
    session_id: undefined,
    timestamp: Math.floor(Date.now() / 1000),
  };
}

function buildToolPath(toolServer: string, toolName: string): string {
  return `/chio/tools/${encodeURIComponent(toolServer)}/${encodeURIComponent(toolName)}`;
}

function anonymousCallerIdentity(): ChioCallerIdentity {
  return {
    subject: "anonymous",
    auth_method: { method: "anonymous" },
    verified: false,
  };
}

function sha256Hex(input: Uint8Array): string {
  return createHash("sha256").update(input).digest("hex");
}

function normalizeReceipt(raw: unknown): ChioReceipt {
  if (raw == null || typeof raw !== "object") {
    throw new ChioClientError(
      "chio_invalid_receipt",
      "sidecar response must be a JSON object",
    );
  }
  const record = raw as Record<string, unknown>;
  const recordDecision = normalizeDecision(record.decision) ?? normalizeDecision(record.verdict);
  if (typeof record.id === "string" && recordDecision != null) {
    return {
      ...record,
      decision: recordDecision,
    } as ChioReceipt;
  }
  if (record.receipt != null && typeof record.receipt === "object") {
    const receipt = record.receipt as Record<string, unknown>;
    const receiptDecision =
      normalizeDecision(receipt.decision)
      ?? normalizeDecision(receipt.verdict)
      ?? normalizeDecision(record.verdict);
    if (typeof receipt.id === "string" && receiptDecision != null) {
      return {
        ...receipt,
        decision: receiptDecision,
      } as ChioReceipt;
    }
  }
  if (typeof record.receipt_id === "string" && typeof record.decision === "string") {
    return {
      ...record,
      id: record.receipt_id,
      decision: {
        verdict: record.decision as ChioVerdict,
        reason: typeof record.reason === "string" ? record.reason : undefined,
      },
    };
  }
  throw new ChioClientError(
    "chio_invalid_receipt",
    "sidecar response missing a recognizable receipt decision shape",
  );
}

function normalizeDecision(raw: unknown): ChioDecision | undefined {
  if (raw == null || typeof raw !== "object") {
    return undefined;
  }
  const record = raw as Record<string, unknown>;
  if (typeof record.verdict !== "string") {
    return undefined;
  }
  switch (record.verdict) {
    case "allow":
      return { verdict: "allow" };
    case "deny":
      return {
        verdict: "deny",
        guard: typeof record.guard === "string" ? record.guard : undefined,
        reason: typeof record.reason === "string" ? record.reason : undefined,
      };
    case "cancel":
      return {
        verdict: "cancel",
        reason: typeof record.reason === "string" ? record.reason : undefined,
      };
    case "incomplete":
      return {
        verdict: "incomplete",
        reason: typeof record.reason === "string" ? record.reason : undefined,
      };
    default:
      return undefined;
  }
}
