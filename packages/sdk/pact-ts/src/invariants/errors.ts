export type PactInvariantErrorCode =
  | "json"
  | "canonical_json"
  | "invalid_hex"
  | "invalid_public_key"
  | "invalid_signature";

export class PactInvariantError extends Error {
  readonly code: PactInvariantErrorCode;

  constructor(code: PactInvariantErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "PactInvariantError";
    this.code = code;
  }
}

export function parseJsonText<T>(input: string): T {
  try {
    return JSON.parse(input) as T;
  } catch (cause) {
    throw new PactInvariantError("json", "input is not valid JSON", { cause });
  }
}
