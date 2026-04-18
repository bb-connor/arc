/**
 * Error types for `@arc-protocol/ai-sdk`.
 *
 * `ArcToolError` is thrown from an ARC-wrapped tool's `execute` callback when
 * the sidecar denies a tool invocation or is otherwise unreachable in
 * fail-closed mode. The Vercel AI SDK surfaces thrown errors to the caller
 * via `onError` / `toolExecutionError`, so this error must preserve the
 * structured verdict fields for downstream handling.
 */

/** Verdict payload attached to an `ArcToolError`. */
export interface ArcToolErrorVerdict {
  /** Kernel verdict, e.g. `"deny"` or `"sidecar_unreachable"`. */
  verdict: "deny" | "cancel" | "incomplete" | "sidecar_unreachable";
  /** Name of the guard that produced the deny decision (empty for transport errors). */
  guard: string;
  /** Human-readable reason supplied by the kernel. */
  reason: string;
  /** Optional signed-receipt identifier, when the sidecar produced one. */
  receiptId?: string | undefined;
}

/**
 * Error thrown when ARC blocks a tool invocation.
 *
 * The Vercel AI SDK will surface this error through its standard error
 * channels (e.g. `result.error`, `onError`). Callers can `instanceof` check
 * to react programmatically.
 */
export class ArcToolError extends Error {
  /** Structured verdict for programmatic handling. */
  readonly verdict: ArcToolErrorVerdict["verdict"];
  /** Guard name (empty string on transport errors). */
  readonly guard: string;
  /** Human-readable reason. */
  readonly reason: string;
  /** Optional signed-receipt identifier, when available. */
  readonly receiptId: string | undefined;

  constructor(payload: ArcToolErrorVerdict) {
    super(`ARC ${payload.verdict}: ${payload.reason}`);
    this.name = "ArcToolError";
    this.verdict = payload.verdict;
    this.guard = payload.guard;
    this.reason = payload.reason;
    this.receiptId = payload.receiptId;
  }
}
