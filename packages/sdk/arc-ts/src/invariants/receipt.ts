import { canonicalizeJson, canonicalizeJsonString } from "./json.ts";
import { sha256Hex, verifyEd25519Signature } from "./crypto.ts";
import { parseJsonText } from "./errors.ts";

export type ReceiptDecisionKind = "allow" | "deny" | "cancelled" | "incomplete";

export interface ToolCallAction {
  parameters: unknown;
  parameter_hash: string;
}

export interface ArcReceipt {
  id: string;
  timestamp: number;
  capability_id: string;
  tool_server: string;
  tool_name: string;
  action: ToolCallAction;
  decision: {
    verdict: ReceiptDecisionKind;
    reason?: string;
    guard?: string;
  };
  content_hash: string;
  policy_hash: string;
  evidence?: Array<{
    guard_name: string;
    verdict: boolean;
    details?: string;
  }>;
  metadata?: unknown;
  kernel_key: string;
  signature: string;
}

export interface ReceiptVerification {
  signature_valid: boolean;
  parameter_hash_valid: boolean;
  decision: ReceiptDecisionKind;
}

export function parseReceiptJson(input: string): ArcReceipt {
  return parseJsonText(input);
}

export function receiptBody(receipt: ArcReceipt): Omit<ArcReceipt, "signature"> {
  const { signature: _signature, ...body } = receipt;
  return body;
}

export function receiptBodyCanonicalJson(receipt: ArcReceipt): string {
  return canonicalizeJson(receiptBody(receipt));
}

export function verifyReceipt(receipt: ArcReceipt): ReceiptVerification {
  const bodyCanonicalJson = receiptBodyCanonicalJson(receipt);
  const parameterCanonicalJson = canonicalizeJson(receipt.action.parameters);

  return {
    signature_valid: verifyEd25519Signature(bodyCanonicalJson, receipt.kernel_key, receipt.signature),
    parameter_hash_valid: receipt.action.parameter_hash === sha256Hex(parameterCanonicalJson),
    decision: receipt.decision.verdict,
  };
}

export function verifyReceiptJson(input: string): ReceiptVerification {
  return verifyReceipt(parseReceiptJson(input));
}

export { canonicalizeJsonString };
