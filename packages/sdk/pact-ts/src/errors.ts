/**
 * SDK-level error hierarchy for PACT TypeScript SDK.
 *
 * PactError is the base for all SDK-level errors.
 * PactInvariantError (in invariants/errors.ts) is a separate, lower-level layer
 * and does NOT extend PactError.
 */

export class PactError extends Error {
  readonly code: string;

  constructor(code: string, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "PactError";
    this.code = code;
  }
}

export class DpopSignError extends PactError {
  constructor(message: string, options?: ErrorOptions) {
    super("dpop_sign_error", message, options);
    this.name = "DpopSignError";
  }
}

export class QueryError extends PactError {
  readonly status: number | undefined;

  constructor(message: string, status?: number, options?: ErrorOptions) {
    super("query_error", message, options);
    this.name = "QueryError";
    this.status = status;
  }
}

export class TransportError extends PactError {
  constructor(message: string, options?: ErrorOptions) {
    super("transport_error", message, options);
    this.name = "TransportError";
  }
}
