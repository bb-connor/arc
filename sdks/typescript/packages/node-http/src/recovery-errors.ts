/** Closed categories emitted by the native recovery host. */
export type RecoveryErrorCode =
  | "recovery.invalid_command" | "recovery.authority_denied"
  | "recovery.conflict" | "recovery.unsupported_profile"
  | "recovery.uncovered_mediation" | "recovery.restart_required"
  | "recovery.unknown_effect" | "recovery.unavailable"
  | "recovery.probe_expired" | "recovery.origin_refused"
  | "recovery.busy" | "recovery.projection_too_large"
  | "recovery.invalid_response" | "recovery.refused_or_unavailable";

export class RecoveryError extends Error {
  constructor(readonly code: RecoveryErrorCode) { super(code); }
}

const hostErrors: Readonly<Record<number, ReadonlySet<string>>> = {
  400: new Set(["recovery.invalid_command"]),
  403: new Set(["recovery.authority_denied"]),
  409: new Set(["recovery.conflict", "recovery.unsupported_profile", "recovery.uncovered_mediation",
    "recovery.restart_required", "recovery.unknown_effect", "recovery.probe_expired", "recovery.origin_refused"]),
  413: new Set(["recovery.projection_too_large"]),
  503: new Set(["recovery.unavailable", "recovery.busy"]),
};

export function nativeError(status: number, bytes: Uint8Array): RecoveryError {
  // No decoding of an unbounded, diagnostic-bearing upstream error message.
  const code = bytes.length <= 64 ? new TextDecoder().decode(bytes) : "";
  return new RecoveryError(hostErrors[status]?.has(code)
    ? code as RecoveryErrorCode : "recovery.refused_or_unavailable");
}
