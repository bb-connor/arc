export type ArcInvariantErrorCode =
  | "json"
  | "canonical_json"
  | "invalid_hex"
  | "invalid_public_key"
  | "invalid_signature";

export class ArcInvariantError extends Error {
  readonly code: ArcInvariantErrorCode;

  constructor(code: ArcInvariantErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "ArcInvariantError";
    this.code = code;
  }
}

export function parseJsonText<T>(input: string): T {
  try {
    return JSON.parse(input) as T;
  } catch (cause) {
    throw new ArcInvariantError("json", "input is not valid JSON", { cause });
  }
}
