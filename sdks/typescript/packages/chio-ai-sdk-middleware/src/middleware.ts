import { wrapLanguageModel, type LanguageModelMiddleware } from "ai";
import { evaluateWithChio, type ChioRuntime } from "./runtime.js";

/** Call options the AI SDK passes to a language-model middleware hook. */
export type LanguageModelInvocation =
  Parameters<NonNullable<LanguageModelMiddleware["transformParams"]>>[0]["params"];

/** Any model accepted by the AI SDK's `wrapLanguageModel`. */
export type ChioWrappableModel = Parameters<typeof wrapLanguageModel>[0]["model"];

export interface ToolUseCandidate {
  name: string;
}

export interface ChioEvaluation {
  verdict: "allow" | "deny";
  reason?: string | undefined;
  receiptId?: string | undefined;
  decision?: "allow" | "deny" | "cancelled" | "incomplete" | undefined;
  receipt_kind?: "mediated_decision" | "trace_observation" | "advisory_evaluation" | undefined;
  boundary_class?: "prevent" | "detect_only" | "advisory_only" | undefined;
  observation_outcome?: "observed" | "evaluated" | "dropped" | undefined;
  trust_level?: "mediated" | "verified" | "advisory" | undefined;
  result?: string | undefined;
  authorized?: boolean | undefined;
  ok?: boolean | undefined;
  signer_trusted?: boolean | undefined;
  signature_valid?: boolean | undefined;
  receipt_id_valid?: boolean | undefined;
  parameter_hash_valid?: boolean | undefined;
  receipt?: Record<string, unknown> | undefined;
}

/**
 * Authority fields produced by trusted receipt verification. These are NOT
 * carried by the raw `/chio/evaluate` response body; they are the output of
 * a downstream signature / parameter-hash / receipt-id verification pass
 * (either the caller-supplied `verifyReceipt` or the `/chio/verify`
 * sidecar route). `isAuthorizedEvaluation` requires every field to be set
 * before authorizing a tool invocation.
 */
export interface ChioReceiptAuthority {
  receipt_kind?: "mediated_decision" | "trace_observation" | "advisory_evaluation" | undefined;
  boundary_class?: "prevent" | "detect_only" | "advisory_only" | undefined;
  trust_level?: "mediated" | "verified" | "advisory" | undefined;
  result?: string | undefined;
  authorized?: boolean | undefined;
  ok?: boolean | undefined;
  signer_trusted?: boolean | undefined;
  signature_valid?: boolean | undefined;
  receipt_id_valid?: boolean | undefined;
  parameter_hash_valid?: boolean | undefined;
}

/**
 * Caller-supplied receipt verifier, typically backed by the trusted
 * `@chio-protocol/sdk` invariants. Receives the raw receipt body returned
 * by `/chio/evaluate` and returns the authority fields the middleware
 * requires before authorizing a tool invocation.
 */
export type ChioReceiptVerifier =
  (receipt: Record<string, unknown>) =>
    ChioReceiptAuthority
    | Promise<ChioReceiptAuthority>;

export type ChioEvaluator = (input: {
  runtime: ChioRuntime;
  request?: LanguageModelInvocation | undefined;
  toolUse?: ToolUseCandidate | undefined;
}) => Promise<ChioEvaluation> | ChioEvaluation;

export interface ChioMiddlewareOptions {
  provider?: string | undefined;
  modelId?: string | undefined;
  runtime?: ChioRuntime | "auto" | undefined;
  sidecarUrl?: string | undefined;
  fetch?: typeof fetch | undefined;
  evaluate?: ChioEvaluator | undefined;
  /**
   * Verifies the signed receipt produced by `/chio/evaluate`. Takes
   * precedence over the `/chio/verify` sidecar fallback. When unset, the
   * middleware POSTs the receipt to the sidecar's `/chio/verify` route
   * using the same default URL (`http://127.0.0.1:9090` when neither
   * `sidecarUrl` nor a per-call override is supplied) that the evaluate
   * path uses, because the raw `/chio/evaluate` response does not carry
   * signer / signature / receipt-id / parameter-hash authority fields.
   */
  verifyReceipt?: ChioReceiptVerifier | undefined;
}

/**
 * Merge a `ChioReceiptAuthority` result onto a `ChioEvaluation` produced by
 * the `/chio/evaluate` round-trip. The authority result is the source of
 * truth for every signer / signature / receipt-id / parameter-hash field,
 * because those values are the *output* of verification, not inputs from
 * the evaluation wire response. Defined fields on `authority` always win
 * over fields already present on the evaluation.
 */
export function mergeAuthority(
  evaluation: ChioEvaluation,
  authority: ChioReceiptAuthority,
): ChioEvaluation {
  const merged: ChioEvaluation = { ...evaluation };
  if (authority.receipt_kind !== undefined) {
    merged.receipt_kind = authority.receipt_kind;
  }
  if (authority.boundary_class !== undefined) {
    merged.boundary_class = authority.boundary_class;
  }
  if (authority.trust_level !== undefined) {
    merged.trust_level = authority.trust_level;
  }
  if (authority.result !== undefined) {
    merged.result = authority.result;
  }
  if (authority.authorized !== undefined) {
    merged.authorized = authority.authorized;
  }
  if (authority.ok !== undefined) {
    merged.ok = authority.ok;
  }
  if (authority.signer_trusted !== undefined) {
    merged.signer_trusted = authority.signer_trusted;
  }
  if (authority.signature_valid !== undefined) {
    merged.signature_valid = authority.signature_valid;
  }
  if (authority.receipt_id_valid !== undefined) {
    merged.receipt_id_valid = authority.receipt_id_valid;
  }
  if (authority.parameter_hash_valid !== undefined) {
    merged.parameter_hash_valid = authority.parameter_hash_valid;
  }
  return merged;
}

export class ChioMiddlewareDeniedError extends Error {
  readonly receiptId: string | undefined;
  readonly reason: string | undefined;

  constructor(evaluation: ChioEvaluation) {
    super(evaluation.reason ?? "Chio denied the language-model tool invocation");
    this.name = "ChioMiddlewareDeniedError";
    this.receiptId = evaluation.receiptId;
    this.reason = evaluation.reason;
  }
}

/// AI SDK 7 language-model middleware. `wrapLanguageModel` calls
/// `wrapGenerate` for `generateText` and `wrapStream` for `streamText`; each
/// evaluates every tool declared on the call before delegating to the model.
export type ChioAiSdkMiddleware = LanguageModelMiddleware & {
  readonly specificationVersion: "v4";
};

export function createChioMiddleware(options: ChioMiddlewareOptions = {}): ChioAiSdkMiddleware {
  return {
    specificationVersion: "v4",
    async wrapGenerate({ doGenerate, params }) {
      await evaluateToolBoundary(params, options);
      return doGenerate();
    },
    async wrapStream({ doStream, params }) {
      await evaluateToolBoundary(params, options);
      return doStream();
    },
  };
}

/// Wrap a model with the Chio middleware via the AI SDK's own
/// `wrapLanguageModel`, so provider, model id and supported URLs carry over.
export function wrapWithChio(
  model: ChioWrappableModel,
  options: ChioMiddlewareOptions = {},
): ReturnType<typeof wrapLanguageModel> {
  return wrapLanguageModel({ model, middleware: createChioMiddleware(options) });
}

async function evaluateToolBoundary(
  request: LanguageModelInvocation,
  options: ChioMiddlewareOptions,
): Promise<void> {
  const toolUses = collectToolUses(request);
  if (toolUses.length === 0) {
    return;
  }
  for (const toolUse of toolUses) {
    const evaluation = await evaluateWithChio(options, {
      runtime: options.runtime,
      request,
      toolUse,
    });
    if (!isAuthorizedEvaluation(evaluation)) {
      throw new ChioMiddlewareDeniedError(nonAuthorizingEvaluation(evaluation));
    }
  }
}

export function isAuthorizedEvaluation(evaluation: ChioEvaluation): boolean {
  return evaluation.verdict === "allow"
    && evaluation.decision === "allow"
    && evaluation.receipt_kind === "mediated_decision"
    && evaluation.boundary_class === "prevent"
    && evaluation.observation_outcome == null
    && evaluation.trust_level === "mediated"
    && isAuthorizedResult(evaluation.result)
    && evaluation.authorized === true
    && evaluation.ok === true
    && evaluation.signer_trusted === true
    && evaluation.signature_valid === true
    && evaluation.receipt_id_valid === true
    && evaluation.parameter_hash_valid === true;
}

function isAuthorizedResult(result: string | undefined): boolean {
  return result === "allow";
}

function nonAuthorizingEvaluation(evaluation: ChioEvaluation): ChioEvaluation {
  if (evaluation.verdict === "deny") {
    return evaluation;
  }
  return {
    ...evaluation,
    verdict: "deny",
    reason: evaluation.reason ?? "Chio evaluation did not include verified receipt authorization",
  };
}

function collectToolUses(request: LanguageModelInvocation): ToolUseCandidate[] {
  return (request.tools ?? [])
    .map(tool => tool.name)
    .sort()
    .map(name => ({ name }));
}
