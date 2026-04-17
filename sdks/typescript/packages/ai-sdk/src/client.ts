/**
 * Minimal HTTP client for the ARC sidecar's tool-call evaluation endpoint.
 *
 * The sidecar exposes `POST /arc/evaluate` which accepts a JSON envelope
 * describing a single tool call (capability, server, name, arguments) and
 * returns either the historical receipt envelope or the Lambda evaluator's
 * flatter `{ receipt_id, decision }` shape. This client normalizes both wire
 * formats to a stable `ArcReceipt` API and stays deliberately small so the
 * Vercel AI SDK wrapper does not pull in the HTTP-substrate surface.
 *
 * Transport uses `globalThis.fetch` (Node >= 20 ships it natively) and
 * supports a pluggable `fetch` override for testing.
 */

/** Canonical decision verdict values returned by the sidecar. */
export type ArcVerdict = "allow" | "deny" | "cancel" | "incomplete";

/** Decision payload embedded in a receipt. */
export interface ArcDecision {
  verdict: ArcVerdict;
  /** Guard name on deny/cancel/incomplete verdicts. */
  guard?: string | undefined;
  /** Human-readable reason on deny/cancel/incomplete verdicts. */
  reason?: string | undefined;
}

/** Minimal shape of a sidecar-issued receipt we care about. */
export interface ArcReceipt {
  id: string;
  decision: ArcDecision;
  // Additional fields (tool_server, tool_name, signature, ...) are ignored
  // by this client but preserved on the wire for higher-level consumers.
  [key: string]: unknown;
}

/** Body of a tool-call evaluation request. */
export interface ArcEvaluateToolCallRequest {
  capability_id?: string | undefined;
  tool_server: string;
  tool_name: string;
  arguments?: unknown;
  parameters?: unknown;
  capability?: unknown;
  /** Caller-supplied metadata persisted in the receipt for observability. */
  metadata?: Record<string, unknown> | undefined;
}

/** Options accepted by the `ArcClient` constructor. */
export interface ArcClientOptions {
  /**
   * Base URL of the ARC sidecar (e.g. `"http://127.0.0.1:9090"`).
   * Defaults to `ARC_SIDECAR_URL` env var or `"http://127.0.0.1:9090"`.
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
  const envUrl = process.env["ARC_SIDECAR_URL"];
  if (envUrl != null && envUrl.length > 0) {
    return envUrl.replace(/\/+$/, "");
  }
  return "http://127.0.0.1:9090";
}

/** Transport/protocol error emitted by the ARC client. */
export class ArcClientError extends Error {
  readonly code: string;
  readonly statusCode: number | undefined;

  constructor(code: string, message: string, statusCode?: number) {
    super(message);
    this.name = "ArcClientError";
    this.code = code;
    this.statusCode = statusCode;
  }
}

/**
 * Minimal client targeting `POST /arc/evaluate` on the ARC sidecar.
 *
 * Intentionally distinct from `@arc-protocol/node-http`'s HTTP-substrate
 * client, which evaluates inbound HTTP requests rather than outbound tool
 * calls. Consumers who need the HTTP substrate should import that package
 * directly; this client is scoped to the Vercel AI SDK tool-call shape.
 */
export class ArcClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly debug: ((message: string, data?: unknown) => void) | undefined;

  constructor(options: ArcClientOptions = {}) {
    this.baseUrl = resolveSidecarUrl(options.sidecarUrl);
    this.timeoutMs = options.timeoutMs ?? 5000;
    const fetchImpl = options.fetch ?? globalThis.fetch;
    if (fetchImpl == null) {
      throw new ArcClientError(
        "arc_fetch_unavailable",
        "no `fetch` implementation available; pass one via `ArcClientOptions.fetch`",
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
   * signed receipt. Throws `ArcClientError` on transport failures; the
   * `decision.verdict` on a returned receipt may still be `"deny"`.
   */
  async evaluateToolCall(
    body: ArcEvaluateToolCallRequest,
    options: { capabilityToken?: string | undefined } = {},
  ): Promise<ArcReceipt> {
    const url = `${this.baseUrl}/arc/evaluate`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    const headers: Record<string, string> = {
      "content-type": "application/json",
      accept: "application/json",
    };
    const normalizedBody: ArcEvaluateToolCallRequest = {
      ...body,
      arguments: body.arguments ?? body.parameters ?? null,
    };
    if (options.capabilityToken != null && options.capabilityToken.length > 0) {
      headers["x-arc-capability"] = options.capabilityToken;
      const capability = parseCapabilityToken(options.capabilityToken);
      normalizedBody.capability = normalizedBody.capability ?? capability;
      if ((normalizedBody.capability_id == null || normalizedBody.capability_id.length === 0)
        && typeof capability.id === "string"
        && capability.id.length > 0) {
        normalizedBody.capability_id = capability.id;
      }
    }

    this.debug?.("arc.evaluate.request", {
      url,
      tool_server: normalizedBody.tool_server,
      tool_name: normalizedBody.tool_name,
    });

    try {
      const response = await this.fetchImpl(url, {
        method: "POST",
        headers,
        body: JSON.stringify(normalizedBody),
        signal: controller.signal,
      });

      if (!response.ok) {
        const text = await response.text().catch(() => "");
        throw new ArcClientError(
          "arc_evaluation_failed",
          `sidecar returned ${response.status}: ${text}`,
          response.status,
        );
      }

      const receipt = normalizeReceipt(await response.json());
      if (receipt == null || typeof receipt !== "object" || receipt.decision == null) {
        throw new ArcClientError(
          "arc_invalid_receipt",
          "sidecar response missing `decision` field",
        );
      }
      this.debug?.("arc.evaluate.response", {
        id: receipt.id,
        verdict: receipt.decision.verdict,
      });
      return receipt;
    } catch (error) {
      if (error instanceof ArcClientError) {
        throw error;
      }
      if (error instanceof DOMException && error.name === "AbortError") {
        throw new ArcClientError(
          "arc_timeout",
          `sidecar request timed out after ${this.timeoutMs}ms`,
        );
      }
      const message = error instanceof Error ? error.message : String(error);
      throw new ArcClientError(
        "arc_sidecar_unreachable",
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
    throw new ArcClientError(
      "arc_invalid_capability",
      `failed to parse capability token JSON: ${message}`,
    );
  }
}

function normalizeReceipt(raw: unknown): ArcReceipt {
  if (raw == null || typeof raw !== "object") {
    throw new ArcClientError(
      "arc_invalid_receipt",
      "sidecar response must be a JSON object",
    );
  }
  const record = raw as Record<string, unknown>;
  if (record.decision != null && typeof record.decision === "object") {
    return record as ArcReceipt;
  }
  if (typeof record.receipt_id === "string" && typeof record.decision === "string") {
    return {
      ...record,
      id: record.receipt_id,
      decision: {
        verdict: record.decision as ArcVerdict,
        reason: typeof record.reason === "string" ? record.reason : undefined,
      },
    };
  }
  throw new ArcClientError(
    "arc_invalid_receipt",
    "sidecar response missing a recognizable receipt decision shape",
  );
}
