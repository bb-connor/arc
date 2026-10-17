import {
  mergeAuthority,
  type ChioEvaluation,
  type ChioMiddlewareOptions,
  type ChioReceiptAuthority,
  type ChioReceiptVerifier,
  type LanguageModelInvocation,
  type ToolUseCandidate,
} from "./middleware.js";

export interface RuntimeEvaluationOptions {
  request?: LanguageModelInvocation | undefined;
  toolUse?: ToolUseCandidate | undefined;
  sidecarUrl?: string | undefined;
  fetch?: typeof fetch | undefined;
}

export async function evaluateWithChio(
  options: ChioMiddlewareOptions,
  runtimeOptions: RuntimeEvaluationOptions = {},
): Promise<ChioEvaluation> {
  if (options.evaluate != null) {
    return options.evaluate({
      request: runtimeOptions.request,
      toolUse: runtimeOptions.toolUse,
    });
  }

  const payload = {
    schema: "chio.ai-sdk-middleware.invocation.v1",
    provider: options.provider,
    model_id: options.modelId,
    tool_use: runtimeOptions.toolUse ?? null,
    request: runtimeOptions.request ?? null,
  };

  const fetchImpl = runtimeOptions.fetch ?? options.fetch ?? globalThis.fetch;
  if (fetchImpl == null) {
    throw new Error("no fetch implementation available for Chio sidecar evaluation");
  }
  const sidecarUrl = resolveSidecarUrl(runtimeOptions.sidecarUrl ?? options.sidecarUrl);
  const response = await fetchImpl(`${sidecarUrl}/chio/evaluate`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json",
    },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    throw new Error(`Chio sidecar returned ${response.status}`);
  }
  const evaluation = normalizeEvaluation(await response.json());

  if (evaluation.verdict !== "allow") {
    return evaluation;
  }

  return applyReceiptAuthority(evaluation, options, runtimeOptions);
}

/**
 * Look up the authority fields that gate `isAuthorizedEvaluation`. The raw
 * `/chio/evaluate` body does NOT carry `signer_trusted`/`signature_valid`/
 * `receipt_id_valid`/`parameter_hash_valid`: those are the *output* of a
 * verification pass. Apply the caller-supplied `verifyReceipt` when
 * available; otherwise fall back to the sidecar's `/chio/verify` route,
 * reusing the same `resolveSidecarUrl` default as the evaluate path so
 * default-configured callers continue to verify. Fail closed when the
 * sidecar response is non-OK or unreachable, when no fetch is available,
 * or when the resulting authority is missing required fields.
 *
 */
async function applyReceiptAuthority(
  evaluation: ChioEvaluation,
  options: ChioMiddlewareOptions,
  runtimeOptions: RuntimeEvaluationOptions,
): Promise<ChioEvaluation> {
  const receipt = evaluation.receipt;
  if (receipt == null) {
    return denyForReason(
      evaluation,
      "Chio evaluate returned allow without a receipt body; cannot verify authority",
    );
  }

  if (options.verifyReceipt != null) {
    let authority: ChioReceiptAuthority;
    try {
      authority = await runVerifyReceipt(options.verifyReceipt, receipt);
    } catch (error) {
      return denyForReason(
        evaluation,
        `Chio verifyReceipt threw before producing authority: ${stringifyError(error)}`,
      );
    }
    return mergeAuthorityOrDeny(evaluation, authority);
  }

  // Reuse the same default localhost sidecar URL that the evaluate path
  // resolves when no `sidecarUrl` is supplied. Without this fallback,
  // every default-configured caller (no verifyReceipt, no sidecarUrl) is
  // denied even though the documented default is the local sidecar at
  // 127.0.0.1:9090 -- which `evaluateWithChio` already used to fetch
  // `/chio/evaluate`. `resolveSidecarUrl` strips trailing slashes and
  // injects the localhost default; the only failure mode is when fetch
  // itself is unavailable in the runtime.
  const base = resolveSidecarUrl(runtimeOptions.sidecarUrl ?? options.sidecarUrl);
  const fetchImpl = runtimeOptions.fetch ?? options.fetch ?? globalThis.fetch;
  if (fetchImpl == null) {
    return denyForReason(
      evaluation,
      "no fetch implementation available for Chio /chio/verify fallback",
    );
  }

  let authority: ChioReceiptAuthority;
  try {
    const response = await fetchImpl(`${base}/chio/verify`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
      },
      // Send the raw receipt body. The Rust `/chio/verify` handler in
      // `crates/products/chio-api-protect/src/proxy.rs::sidecar_verify_handler`
      // deserializes the request body directly as `HttpReceipt`, so
      // wrapping it as `{ receipt }` would cause the real sidecar to
      // return 400 bad_request.
      body: JSON.stringify(receipt),
    });
    if (!response.ok) {
      return denyForReason(
        evaluation,
        `Chio /chio/verify returned ${response.status}`,
      );
    }
    const body = (await response.json()) as unknown;
    authority = readAuthority(body);
  } catch (error) {
    return denyForReason(
      evaluation,
      `Chio /chio/verify unreachable: ${stringifyError(error)}`,
    );
  }

  return mergeAuthorityOrDeny(evaluation, authority);
}

function mergeAuthorityOrDeny(
  evaluation: ChioEvaluation,
  authority: ChioReceiptAuthority,
): ChioEvaluation {
  const missing = missingAuthorityFields(authority);
  if (missing.length > 0) {
    return denyForReason(
      evaluation,
      `Chio receipt authority is missing required fields: ${missing.join(", ")}`,
    );
  }
  return mergeAuthority(evaluation, authority);
}

function missingAuthorityFields(authority: ChioReceiptAuthority): string[] {
  const missing: string[] = [];
  if (authority.signer_trusted == null) {
    missing.push("signer_trusted");
  }
  if (authority.signature_valid == null) {
    missing.push("signature_valid");
  }
  if (authority.receipt_id_valid == null) {
    missing.push("receipt_id_valid");
  }
  if (authority.parameter_hash_valid == null) {
    missing.push("parameter_hash_valid");
  }
  return missing;
}

function readAuthority(value: unknown): ChioReceiptAuthority {
  if (value == null || typeof value !== "object") {
    return {};
  }
  const record = value as Record<string, unknown>;
  return {
    receipt_kind: receiptKindValue(stringField(record, "receipt_kind")),
    boundary_class: boundaryClassValue(stringField(record, "boundary_class")),
    trust_level: trustLevelValue(stringField(record, "trust_level")),
    result: stringField(record, "result"),
    authorized: booleanField(record, "authorized"),
    ok: booleanField(record, "ok"),
    signer_trusted: booleanField(record, "signer_trusted"),
    signature_valid: booleanField(record, "signature_valid"),
    receipt_id_valid: booleanField(record, "receipt_id_valid"),
    parameter_hash_valid: booleanField(record, "parameter_hash_valid"),
  };
}

async function runVerifyReceipt(
  verifier: ChioReceiptVerifier,
  receipt: Record<string, unknown>,
): Promise<ChioReceiptAuthority> {
  const result = verifier(receipt);
  return result instanceof Promise ? result : Promise.resolve(result);
}

function denyForReason(evaluation: ChioEvaluation, reason: string): ChioEvaluation {
  return {
    ...evaluation,
    verdict: "deny",
    reason,
  };
}

function stringifyError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  if (typeof error === "string") {
    return error;
  }
  try {
    return JSON.stringify(error);
  } catch {
    return "unknown error";
  }
}

function resolveSidecarUrl(value: string | undefined): string {
  return (value ?? "http://127.0.0.1:9090").replace(/\/+$/, "");
}

function normalizeEvaluation(value: unknown): ChioEvaluation {
  if (value != null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const receipt = record["receipt"];
    const receiptRecord = receipt != null && typeof receipt === "object"
      ? receipt as Record<string, unknown>
      : undefined;
    const verdict = record["verdict"];
    if (verdict != null && typeof verdict === "object") {
      const nested = verdict as Record<string, unknown>;
      if (nested["verdict"] === "allow" || nested["verdict"] === "deny") {
        return {
          verdict: nested["verdict"],
          reason: typeof nested["reason"] === "string" ? nested["reason"] : undefined,
          ...evaluationFields(receiptRecord),
        };
      }
    }
  }
  throw new Error("Chio evaluation response did not include an allow or deny verdict");
}

/**
 * Pull out the non-authority fields the evaluation response itself carries
 * (receipt id, decision verdict, observation_outcome). Authority fields
 * (signer / signature / receipt-id / parameter-hash) are deliberately NOT
 * read here: they are the output of a downstream verification step and are
 * layered on top via `applyReceiptAuthority`. The receipt body is preserved
 * so the verification step can inspect it.
 */
function evaluationFields(
  receipt: Record<string, unknown> | undefined,
): Omit<ChioEvaluation, "verdict" | "reason"> {
  return {
    receiptId: stringField(receipt, "id"),
    decision: decisionValue(readVerdictTag(receipt?.["verdict"])),
    observation_outcome: observationOutcomeValue(stringField(receipt, "observation_outcome")),
    receipt,
  };
}

/** Read the tag of a Rust-style tagged verdict object `{ verdict: "allow", ... }`. */
function readVerdictTag(value: unknown): string | undefined {
  if (value != null && typeof value === "object") {
    const nested = (value as Record<string, unknown>)["verdict"];
    if (typeof nested === "string") {
      return nested;
    }
  }
  return undefined;
}

function stringField(value: unknown, key: string): string | undefined {
  if (value != null && typeof value === "object") {
    const found = (value as Record<string, unknown>)[key];
    return typeof found === "string" ? found : undefined;
  }
  return undefined;
}

function booleanField(value: Record<string, unknown>, key: string): boolean | undefined {
  const found = value[key];
  return typeof found === "boolean" ? found : undefined;
}

function decisionValue(value: string | undefined): ChioEvaluation["decision"] {
  return value === "allow" || value === "deny" || value === "cancelled" || value === "incomplete"
    ? value
    : undefined;
}

function receiptKindValue(value: string | undefined): ChioEvaluation["receipt_kind"] {
  return value === "mediated_decision"
    || value === "trace_observation"
    || value === "advisory_evaluation"
    ? value
    : undefined;
}

function boundaryClassValue(value: string | undefined): ChioEvaluation["boundary_class"] {
  return value === "prevent"
    || value === "detect_only"
    || value === "advisory_only"
    ? value
    : undefined;
}

function trustLevelValue(value: string | undefined): ChioEvaluation["trust_level"] {
  return value === "mediated" || value === "verified" || value === "advisory"
    ? value
    : undefined;
}

function observationOutcomeValue(value: string | undefined): ChioEvaluation["observation_outcome"] {
  return value === "observed" || value === "evaluated" || value === "dropped"
    ? value
    : undefined;
}
