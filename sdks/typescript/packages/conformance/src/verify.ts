/**
 * Receipt verification utilities for conformance tests.
 *
 * These functions mirror the Rust kernel's receipt verification logic
 * and can be used to validate that receipts produced by the TS SDK
 * match the expected format.
 */

import { createHash } from "node:crypto";
import type { HttpReceipt, Verdict, GuardEvidence } from "@chio-protocol/node-http";
import { canonicalJsonString } from "./canonical.js";

/**
 * Verify that a receipt has all required fields and valid structure.
 */
export function validateReceiptStructure(receipt: HttpReceipt): string[] {
  const errors: string[] = [];

  if (typeof receipt.id !== "string" || receipt.id.length === 0) {
    errors.push("receipt.id must be a non-empty string");
  }

  if (typeof receipt.request_id !== "string" || receipt.request_id.length === 0) {
    errors.push("receipt.request_id must be a non-empty string");
  }

  if (typeof receipt.route_pattern !== "string") {
    errors.push("receipt.route_pattern must be a string");
  }

  const validMethods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
  if (!validMethods.includes(receipt.method)) {
    errors.push(`receipt.method must be one of ${validMethods.join(", ")}`);
  }

  if (typeof receipt.caller_identity_hash !== "string" || receipt.caller_identity_hash.length !== 64) {
    errors.push("receipt.caller_identity_hash must be a 64-character hex string");
  }

  if (!isValidVerdict(receipt.verdict)) {
    errors.push("receipt.verdict must be a valid Verdict");
  }

  if (!Array.isArray(receipt.evidence)) {
    errors.push("receipt.evidence must be an array");
  } else {
    for (const [i, ev] of receipt.evidence.entries()) {
      if (typeof ev.guard_name !== "string") {
        errors.push(`receipt.evidence[${i}].guard_name must be a string`);
      }
      if (typeof ev.verdict !== "boolean") {
        errors.push(`receipt.evidence[${i}].verdict must be a boolean`);
      }
    }
  }

  if (typeof receipt.response_status !== "number" || receipt.response_status < 100 || receipt.response_status > 599) {
    errors.push("receipt.response_status must be a valid HTTP status code");
  }

  if (typeof receipt.timestamp !== "number" || receipt.timestamp <= 0) {
    errors.push("receipt.timestamp must be a positive number");
  }

  if (typeof receipt.content_hash !== "string" || receipt.content_hash.length !== 64) {
    errors.push("receipt.content_hash must be a 64-character hex string");
  }

  if (typeof receipt.policy_hash !== "string" || receipt.policy_hash.length === 0) {
    errors.push("receipt.policy_hash must be a non-empty string");
  }

  if (typeof receipt.kernel_key !== "string" || receipt.kernel_key.length === 0) {
    errors.push("receipt.kernel_key must be a non-empty string");
  }

  if (typeof receipt.signature !== "string" || receipt.signature.length === 0) {
    errors.push("receipt.signature must be a non-empty string");
  }

  return errors;
}

/**
 * Verify that the content hash in a receipt matches the expected
 * canonical JSON representation of the request content binding.
 */
export function verifyContentHash(
  receipt: HttpReceipt,
  expectedMethod: string,
  expectedRoutePattern: string,
  expectedPath: string,
  expectedQuery: Record<string, string>,
  expectedBodyHash: string | null,
): boolean {
  const binding = {
    body_hash: expectedBodyHash,
    method: expectedMethod,
    path: expectedPath,
    query: expectedQuery,
    route_pattern: expectedRoutePattern,
  };

  const canonical = canonicalJsonString(binding);
  const hash = createHash("sha256").update(canonical, "utf-8").digest("hex");
  return hash === receipt.content_hash;
}

/**
 * Check that a receipt verdict matches expected values.
 */
export function assertVerdictMatch(
  actual: Verdict,
  expected: {
    verdict: "allow" | "deny" | "cancel" | "incomplete";
    reason?: string;
    guard?: string;
    http_status?: number;
  },
): string[] {
  const errors: string[] = [];

  if (actual.verdict !== expected.verdict) {
    errors.push(`expected verdict "${expected.verdict}", got "${actual.verdict}"`);
    return errors;
  }

  if (expected.verdict === "deny" && actual.verdict === "deny") {
    if (expected.reason != null && actual.reason !== expected.reason) {
      errors.push(`expected deny reason "${expected.reason}", got "${actual.reason}"`);
    }
    if (expected.guard != null && actual.guard !== expected.guard) {
      errors.push(`expected deny guard "${expected.guard}", got "${actual.guard}"`);
    }
    if (expected.http_status != null && actual.http_status !== expected.http_status) {
      errors.push(`expected deny http_status ${expected.http_status}, got ${actual.http_status}`);
    }
  }

  return errors;
}

function isValidVerdict(v: Verdict): boolean {
  if (v.verdict === "allow") return true;
  if (v.verdict === "deny") return typeof v.reason === "string" && typeof v.guard === "string";
  if (v.verdict === "cancel") return typeof v.reason === "string";
  if (v.verdict === "incomplete") return typeof v.reason === "string";
  return false;
}
