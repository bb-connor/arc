import { canonicalizeJson, canonicalizeJsonString, parseJsonTextUniqueKeys } from "./json.ts";
import { publicKeyHexMatches, sha256Hex, verifyChioSignature } from "./crypto.ts";
import { ChioInvariantError } from "./errors.ts";

function safeVerifyReceiptSignature(
  signedBytes: string,
  signature: string,
  publicKey: string,
): boolean {
  try {
    return verifyChioSignature(signedBytes, signature, publicKey);
  } catch (error) {
    if (error instanceof ChioInvariantError) {
      // Fail-closed: receipts signed with unsupported algorithms or malformed
      // keys/signatures verify as false rather than propagating an exception.
      return false;
    }
    throw error;
  }
}

export type ReceiptDecisionKind = "allow" | "deny" | "cancelled" | "incomplete" | "none";

export interface ToolCallAction {
  parameters: unknown;
  parameter_hash: string;
}

export interface ChioReceipt {
  id: string;
  timestamp: number;
  capability_id: string;
  tool_server: string;
  tool_name: string;
  action: ToolCallAction;
  decision?: {
    verdict: ReceiptDecisionKind;
    reason?: string;
    guard?: string;
  };
  receipt_kind: string;
  boundary_class: string;
  observation_outcome?: string | null;
  tool_origin: string;
  redaction_mode: string;
  actor_chain?: Array<{
    actor_id: string;
    actor_kind?: string;
  }>;
  content_hash: string;
  policy_hash: string;
  evidence?: Array<{
    guard_name: string;
    verdict: boolean;
    details?: string;
  }>;
  metadata?: unknown;
  trust_level: "mediated" | "verified" | "advisory" | string;
  tenant_id?: string;
  kernel_key: string;
  algorithm?: unknown;
  signature: string;
}

export interface ReceiptVerification {
  signature_valid: boolean;
  parameter_hash_valid: boolean;
  receipt_id_valid: boolean;
  decision: ReceiptDecisionKind;
  receipt_kind: string;
  boundary_class: string;
  trust_level: string;
  result: string;
  authorized: boolean;
  signer_key_hex: string;
  signer_trusted: boolean;
  ok: boolean;
}

const RECEIPT_MEMBERS = new Set([
  "action",
  "actor_chain",
  "algorithm",
  "bbs_projection_version",
  "bbs_signature",
  "boundary_class",
  "capability_id",
  "content_hash",
  "decision",
  "evidence",
  "id",
  "kernel_key",
  "metadata",
  "observation_outcome",
  "policy_hash",
  "receipt_kind",
  "redaction_mode",
  "signature",
  "tenant_id",
  "timestamp",
  "tool_name",
  "tool_origin",
  "tool_server",
  "trust_level",
]);
const ACTION_MEMBERS = new Set(["parameters", "parameter_hash"]);
const ACTOR_MEMBERS = new Set(["actor_id", "actor_kind"]);
const EVIDENCE_MEMBERS = new Set(["guard_name", "verdict", "details"]);
const BBS_SIGNATURE_MEMBERS = new Set([
  "schema",
  "projection_version",
  "algorithm",
  "ciphersuite",
  "issuer_fingerprint",
  "issuer_public_key_hex",
  "message_count",
  "signature_hex",
]);
const DECISION_MEMBERS: Record<string, Set<string>> = {
  allow: new Set(["verdict"]),
  deny: new Set(["verdict", "reason", "guard"]),
  cancelled: new Set(["verdict", "reason"]),
  incomplete: new Set(["verdict", "reason"]),
};

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireMembers(value: unknown, allowed: Set<string>, path: string): void {
  if (!isObject(value)) {
    return;
  }
  for (const key of Object.keys(value).sort()) {
    if (!allowed.has(key)) {
      throw new ChioInvariantError("json", `unknown receipt member: ${path}/${key}`);
    }
  }
}

/** Refuse any member the signed receipt shape does not define. */
function requireClosedReceipt(receipt: ChioReceipt): void {
  const value: unknown = receipt;
  if (!isObject(value)) {
    return;
  }
  requireMembers(value, RECEIPT_MEMBERS, "");
  requireMembers(value.action, ACTION_MEMBERS, "/action");
  requireMembers(value.bbs_signature, BBS_SIGNATURE_MEMBERS, "/bbs_signature");
  const decision = value.decision;
  if (isObject(decision)) {
    const verdict = typeof decision.verdict === "string" ? decision.verdict : "";
    requireMembers(decision, DECISION_MEMBERS[verdict] ?? new Set(["verdict"]), "/decision");
  }
  for (const [name, allowed] of [
    ["actor_chain", ACTOR_MEMBERS],
    ["evidence", EVIDENCE_MEMBERS],
  ] as const) {
    const entries = value[name];
    if (Array.isArray(entries)) {
      entries.forEach((entry, index) => requireMembers(entry, allowed, `/${name}/${index}`));
    }
  }
}

/** Signed receipt text; a repeated object key at any depth throws a `json` ChioInvariantError. */
export function parseReceiptJson(input: string): ChioReceipt {
  return parseJsonTextUniqueKeys(input);
}

export function receiptBody(receipt: ChioReceipt): Omit<ChioReceipt, "algorithm" | "signature"> {
  const { signature: _signature, algorithm: _algorithm, ...body } = receipt;
  return Object.fromEntries(Object.entries(body).filter(([, value]) => value !== null)) as Omit<
    ChioReceipt,
    "algorithm" | "signature"
  >;
}

export function receiptBodyCanonicalJson(receipt: ChioReceipt): string {
  return canonicalizeJson(receiptBody(receipt));
}

function receiptIdInput(receipt: ChioReceipt): Record<string, unknown> {
  const input: Record<string, unknown> = {
    action: receipt.action,
    capability_id: receipt.capability_id,
    content_hash: receipt.content_hash,
    receipt_kind: receipt.receipt_kind,
    boundary_class: receipt.boundary_class,
    tool_origin: receipt.tool_origin,
    redaction_mode: receipt.redaction_mode,
    kernel_key: receipt.kernel_key,
    policy_hash: receipt.policy_hash,
    timestamp: receipt.timestamp,
    tool_name: receipt.tool_name,
    tool_server: receipt.tool_server,
  };
  if (receipt.evidence !== undefined && receipt.evidence.length > 0) {
    input.evidence = receipt.evidence;
  }
  if (receipt.decision !== undefined) {
    input.decision = receipt.decision;
  }
  if (receipt.observation_outcome != null) {
    input.observation_outcome = receipt.observation_outcome;
  }
  if (receipt.actor_chain !== undefined && receipt.actor_chain.length > 0) {
    input.actor_chain = receipt.actor_chain;
  }
  if (receipt.metadata !== undefined && receipt.metadata !== null) {
    input.metadata = receipt.metadata;
  }
  input.trust_level = receipt.trust_level;
  if (receipt.tenant_id !== undefined) {
    input.tenant_id = receipt.tenant_id;
  }
  return input;
}

function contentAddressedReceiptId(receipt: ChioReceipt): string {
  return sha256Hex(canonicalizeJson(receiptIdInput(receipt)));
}

export function receiptSigningBodyCanonicalJson(receipt: ChioReceipt): string {
  return canonicalizeJson({
    id: receipt.id,
    body: receiptIdInput(receipt),
  });
}

function receiptSemantics(receipt: ChioReceipt): { receipt_kind: string; boundary_class: string } {
  return { receipt_kind: receipt.receipt_kind, boundary_class: receipt.boundary_class };
}

function resultLabel(semanticAuthorized: boolean, receiptKind: string, decision: ReceiptDecisionKind): string {
  if (semanticAuthorized) {
    return "Authorized";
  }
  if (receiptKind === "trace_observation") {
    return "Observed";
  }
  if (receiptKind === "advisory_evaluation") {
    return "Advisory";
  }
  switch (decision) {
    case "allow":
      return "Allowed";
    case "deny":
      return "Denied";
    case "cancelled":
      return "Cancelled";
    case "incomplete":
      return "Incomplete";
    case "none":
      return "Invalid";
  }
}

function validObservationOutcome(value: string | null | undefined): boolean {
  return value === "observed" || value === "evaluated" || value === "dropped";
}

function semanticallySignable(receipt: ChioReceipt, decision: ReceiptDecisionKind): boolean {
  if (receipt.receipt_kind === "mediated_decision") {
    return (
      receipt.boundary_class === "prevent" &&
      receipt.trust_level === "mediated" &&
      decision !== "none" &&
      receipt.observation_outcome == null
    );
  }
  if (receipt.receipt_kind === "trace_observation") {
    return (
      receipt.boundary_class === "detect_only" &&
      receipt.trust_level === "verified" &&
      decision === "none" &&
      validObservationOutcome(receipt.observation_outcome)
    );
  }
  if (receipt.receipt_kind === "advisory_evaluation") {
    return (
      receipt.boundary_class === "advisory_only" &&
      receipt.trust_level === "advisory" &&
      decision === "none" &&
      validObservationOutcome(receipt.observation_outcome)
    );
  }
  return false;
}

export function verifyReceipt(receipt: ChioReceipt, trustedSigners: string[] = []): ReceiptVerification {
  requireClosedReceipt(receipt);
  const signingBodyCanonicalJson = receiptSigningBodyCanonicalJson(receipt);
  const parameterCanonicalJson = canonicalizeJson(receipt.action.parameters);
  const decision = receipt.decision?.verdict ?? "none";
  const semantics = receiptSemantics(receipt);
  const semanticAuthorized =
    semantics.receipt_kind === "mediated_decision" &&
    semantics.boundary_class === "prevent" &&
    receipt.trust_level === "mediated" &&
    receipt.observation_outcome == null &&
    decision === "allow";
  const signerTrusted =
    trustedSigners.length > 0 && trustedSigners.some((signer) => publicKeyHexMatches(signer, receipt.kernel_key));
  const receiptIdValid = receipt.id === contentAddressedReceiptId(receipt);
  const signatureValid =
    receiptIdValid &&
    semanticallySignable(receipt, decision) &&
    safeVerifyReceiptSignature(signingBodyCanonicalJson, receipt.signature, receipt.kernel_key);
  const parameterHashValid = receipt.action.parameter_hash === sha256Hex(parameterCanonicalJson);
  const authorized = semanticAuthorized && signatureValid && parameterHashValid && receiptIdValid && signerTrusted;

  return {
    signature_valid: signatureValid,
    parameter_hash_valid: parameterHashValid,
    receipt_id_valid: receiptIdValid,
    decision,
    receipt_kind: semantics.receipt_kind,
    boundary_class: semantics.boundary_class,
    trust_level: receipt.trust_level,
    result: resultLabel(semanticAuthorized, semantics.receipt_kind, decision),
    authorized,
    signer_key_hex: receipt.kernel_key,
    signer_trusted: signerTrusted,
    ok: signatureValid && parameterHashValid && receiptIdValid && signerTrusted,
  };
}

export function verifyReceiptWithTrustedSigners(
  receipt: ChioReceipt,
  trustedSigners: string[],
): ReceiptVerification {
  return verifyReceipt(receipt, trustedSigners);
}

export function verifyReceiptJson(input: string): ReceiptVerification {
  return verifyReceipt(parseReceiptJson(input));
}

export { canonicalizeJsonString };
