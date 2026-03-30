/**
 * SDK-level error hierarchy for ARC TypeScript SDK.
 *
 * ArcError is the base for all SDK-level errors.
 * ArcInvariantError (in invariants/errors.ts) is a separate, lower-level layer
 * and does NOT extend ArcError.
 */

export class ArcError extends Error {
  readonly code: string;

  constructor(code: string, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "ArcError";
    this.code = code;
  }
}

export class DpopSignError extends ArcError {
  constructor(message: string, options?: ErrorOptions) {
    super("dpop_sign_error", message, options);
    this.name = "DpopSignError";
  }
}

export class QueryError extends ArcError {
  readonly status: number | undefined;

  constructor(message: string, status?: number, options?: ErrorOptions) {
    super("query_error", message, options);
    this.name = "QueryError";
    this.status = status;
  }
}

export class TransportError extends ArcError {
  constructor(message: string, options?: ErrorOptions) {
    super("transport_error", message, options);
    this.name = "TransportError";
  }
}
