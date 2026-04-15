/**
 * Core types for the ARC HTTP substrate.
 *
 * These types mirror the Rust arc-http-core crate and define the contract
 * between TypeScript middleware and the ARC sidecar kernel.
 */

// -- HTTP Method --

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";

/** Whether an HTTP method is considered side-effect-free. */
export function isMethodSafe(method: HttpMethod): boolean {
  return method === "GET" || method === "HEAD" || method === "OPTIONS";
}

// -- Auth Method (tagged union matching Rust serde) --

export type AuthMethod =
  | { method: "bearer"; token_hash: string }
  | { method: "api_key"; key_name: string; key_hash: string }
  | { method: "cookie"; cookie_name: string; cookie_hash: string }
  | { method: "mtls_certificate"; subject_dn: string; fingerprint: string }
  | { method: "anonymous" };

// -- Caller Identity --

export interface CallerIdentity {
  /** Stable identifier for the caller (e.g., user ID, service account). */
  subject: string;
  /** How the caller authenticated. */
  auth_method: AuthMethod;
  /** Whether this identity has been cryptographically verified. */
  verified: boolean;
  /** Optional tenant or organization. */
  tenant?: string | undefined;
  /** Optional agent identifier when the caller is an AI agent. */
  agent_id?: string | undefined;
}

// -- Verdict (tagged union matching Rust serde) --

export type Verdict =
  | { verdict: "allow" }
  | { verdict: "deny"; reason: string; guard: string; http_status: number }
  | { verdict: "cancel"; reason: string }
  | { verdict: "incomplete"; reason: string };

export function isAllowed(verdict: Verdict): verdict is { verdict: "allow" } {
  return verdict.verdict === "allow";
}

export function isDenied(verdict: Verdict): verdict is { verdict: "deny"; reason: string; guard: string; http_status: number } {
  return verdict.verdict === "deny";
}

// -- Guard Evidence --

export interface GuardEvidence {
  guard_name: string;
  verdict: boolean;
  details?: string | undefined;
}

// -- HTTP Receipt --

export interface HttpReceipt {
  id: string;
  request_id: string;
  route_pattern: string;
  method: HttpMethod;
  caller_identity_hash: string;
  session_id?: string | undefined;
  verdict: Verdict;
  evidence: GuardEvidence[];
  // ARC evaluation-time HTTP status; allow receipts may be signed before the
  // downstream response exists.
  response_status: number;
  timestamp: number;
  content_hash: string;
  policy_hash: string;
  capability_id?: string | undefined;
  metadata?: unknown;
  kernel_key: string;
  signature: string;
}

// -- ARC HTTP Request (sent to sidecar for evaluation) --

export interface ArcHttpRequest {
  request_id: string;
  method: HttpMethod;
  route_pattern: string;
  path: string;
  query: Record<string, string>;
  headers: Record<string, string>;
  caller: CallerIdentity;
  body_hash?: string | undefined;
  body_length: number;
  session_id?: string | undefined;
  capability_id?: string | undefined;
  timestamp: number;
}

// -- Sidecar evaluate response --

export interface EvaluateResponse {
  verdict: Verdict;
  receipt: HttpReceipt;
  evidence: GuardEvidence[];
}

/**
 * Explicit passthrough state when ARC is configured fail-open and the sidecar
 * could not produce a signed evaluation result.
 */
export interface ArcPassthrough {
  mode: "allow_without_receipt";
  error: typeof ARC_ERROR_CODES.SIDECAR_UNREACHABLE;
  message: string;
}

// -- ARC middleware configuration --

export interface ArcConfig {
  /**
   * URL of the ARC sidecar kernel (e.g., "http://127.0.0.1:9090").
   * Defaults to ARC_SIDECAR_URL env var or "http://127.0.0.1:9090".
   */
  sidecarUrl?: string | undefined;

  /**
   * Path to arc.yaml config file. When provided, the sidecar reads
   * route patterns and policies from this file.
   */
  config?: string | undefined;

  /**
   * Custom identity extractor. Override the default header-based extraction.
   */
  identityExtractor?: IdentityExtractor | undefined;

  /**
   * Route pattern resolver. Maps a raw request path to a pattern
   * (e.g., "/pets/42" -> "/pets/{petId}").
   */
  routePatternResolver?: RoutePatternResolver | undefined;

  /**
   * Called when the sidecar is unreachable. Defaults to deny (fail-closed).
   * `allow` forwards the request without an ARC receipt.
   */
  onSidecarError?: "deny" | "allow" | undefined;

  /**
   * Timeout in milliseconds for sidecar HTTP calls. Default: 5000.
   */
  timeoutMs?: number | undefined;

  /**
   * Headers to forward to the sidecar for policy evaluation.
   * Default: ["content-type", "content-length"].
   */
  forwardHeaders?: string[] | undefined;
}

/** Extract caller identity from an incoming HTTP request. */
export type IdentityExtractor = (headers: Record<string, string | string[] | undefined>) => CallerIdentity;

/** Resolve a raw request path to a route pattern. */
export type RoutePatternResolver = (method: HttpMethod, path: string) => string;

// -- ARC error codes for HTTP responses --

export const ARC_ERROR_CODES = {
  ACCESS_DENIED: "arc_access_denied",
  SIDECAR_UNREACHABLE: "arc_sidecar_unreachable",
  EVALUATION_FAILED: "arc_evaluation_failed",
  INVALID_RECEIPT: "arc_invalid_receipt",
  TIMEOUT: "arc_timeout",
} as const;

export type ArcErrorCode = typeof ARC_ERROR_CODES[keyof typeof ARC_ERROR_CODES];

/** Structured error response body. */
export interface ArcErrorResponse {
  error: ArcErrorCode;
  message: string;
  receipt_id?: string | undefined;
  suggestion?: string | undefined;
}
