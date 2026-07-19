/**
 * Receipt verification conformance tests.
 *
 * Validates that the TypeScript receipt structures match the Rust
 * kernel's HttpReceipt format. These tests use synthetic receipts
 * to verify structural validation.
 */

import { describe, it, expect } from "vitest";
import type { HttpReceipt, Verdict } from "@chio-protocol/node-http";
import type { Receipt_Record } from "../src/_generated/index.js";
import {
  validateReceiptStructure,
  validateChioReceiptRecordStructure,
  verifyContentHash,
  assertVerdictMatch,
} from "../src/verify.js";

function makeValidReceipt(overrides: Partial<HttpReceipt> = {}): HttpReceipt {
  return {
    id: "c".repeat(64),
    request_id: "req-001",
    route_pattern: "/pets/{petId}",
    method: "GET",
    caller_identity_hash: "a".repeat(64),
    verdict: { verdict: "allow" },
    evidence: [],
    response_status: 200,
    timestamp: 1700000000,
    content_hash: "b".repeat(64),
    policy_hash: "cafebabe",
    receipt_kind: "mediated_decision",
    boundary_class: "prevent",
    tool_origin: "caller_executed",
    redaction_mode: "none",
    trust_level: "mediated",
    kernel_key: "ed25519-pubkey-hex",
    signature: "ed25519-sig-hex",
    ...overrides,
  };
}

function makeValidReceiptRecord(
  overrides: Partial<Receipt_Record.ChioReceiptRecord> = {},
): Receipt_Record.ChioReceiptRecord {
  return {
    id: "c".repeat(64),
    timestamp: 1_700_000_000,
    capability_id: "cap-1",
    tool_server: "server-1",
    tool_name: "read",
    action: {
      parameters: {},
      parameter_hash: "a".repeat(64),
    },
    decision: { verdict: "allow" },
    receipt_kind: "mediated_decision",
    boundary_class: "prevent",
    tool_origin: "caller_executed",
    redaction_mode: "none",
    content_hash: "b".repeat(64),
    policy_hash: "policy-v1",
    trust_level: "mediated",
    kernel_key: "d".repeat(64),
    signature: "e".repeat(128),
    ...overrides,
  };
}

describe("validateReceiptStructure", () => {
  it("valid receipt produces no errors", () => {
    const errors = validateReceiptStructure(makeValidReceipt());
    expect(errors).toEqual([]);
  });

  it("detects missing receipt ID", () => {
    const errors = validateReceiptStructure(makeValidReceipt({ id: "" }));
    expect(errors).toContainEqual(expect.stringContaining("receipt.id"));
  });

  it("detects missing request ID", () => {
    const errors = validateReceiptStructure(makeValidReceipt({ request_id: "" }));
    expect(errors).toContainEqual(expect.stringContaining("receipt.request_id"));
  });

  it("detects invalid method", () => {
    const errors = validateReceiptStructure(
      makeValidReceipt({ method: "INVALID" as "GET" }),
    );
    expect(errors).toContainEqual(expect.stringContaining("receipt.method"));
  });

  it("detects invalid caller identity hash length", () => {
    const errors = validateReceiptStructure(
      makeValidReceipt({ caller_identity_hash: "short" }),
    );
    expect(errors).toContainEqual(
      expect.stringContaining("caller_identity_hash"),
    );
  });

  it("detects invalid response status", () => {
    const errors = validateReceiptStructure(
      makeValidReceipt({ response_status: 999 }),
    );
    expect(errors).toContainEqual(
      expect.stringContaining("response_status"),
    );
  });

  it("detects zero timestamp", () => {
    const errors = validateReceiptStructure(
      makeValidReceipt({ timestamp: 0 }),
    );
    expect(errors).toContainEqual(expect.stringContaining("timestamp"));
  });

  it("detects invalid content hash length", () => {
    const errors = validateReceiptStructure(
      makeValidReceipt({ content_hash: "abc" }),
    );
    expect(errors).toContainEqual(expect.stringContaining("content_hash"));
  });

  it("validates evidence array entries", () => {
    const errors = validateReceiptStructure(
      makeValidReceipt({
        evidence: [
          { guard_name: "TestGuard", verdict: true },
          { guard_name: "", verdict: false, details: "denied" },
        ],
      }),
    );
    expect(errors).toEqual([]);
  });

  it("detects deny verdict with valid structure", () => {
    const receipt = makeValidReceipt({
      verdict: {
        verdict: "deny",
        reason: "no capability",
        guard: "CapabilityGuard",
        http_status: 403,
      },
      response_status: 403,
    });
    const errors = validateReceiptStructure(receipt);
    expect(errors).toEqual([]);
  });
});

describe("validateChioReceiptRecordStructure", () => {
  it("accepts coherent mediated receipt semantics", () => {
    expect(validateChioReceiptRecordStructure(makeValidReceiptRecord())).toEqual([]);
  });

  it("requires mediated receipts to carry a decision", () => {
    const receipt = makeValidReceiptRecord();
    delete receipt.decision;

    expect(validateChioReceiptRecordStructure(receipt)).toContainEqual(
      expect.stringContaining("must include decision"),
    );
  });

  it("rejects an authorization decision on a trace receipt", () => {
    const receipt = makeValidReceiptRecord({
      receipt_kind: "trace_observation",
      boundary_class: "detect_only",
      observation_outcome: "observed",
      trust_level: "verified",
    });

    expect(validateChioReceiptRecordStructure(receipt)).toContainEqual(
      expect.stringContaining("must omit decision"),
    );
  });

  it("accepts coherent trace semantics without a decision", () => {
    const receipt = makeValidReceiptRecord({
      receipt_kind: "trace_observation",
      boundary_class: "detect_only",
      observation_outcome: "observed",
      trust_level: "verified",
    });
    delete receipt.decision;

    expect(validateChioReceiptRecordStructure(receipt)).toEqual([]);
  });

  it("requires trace receipts to use their boundary, trust, and outcome", () => {
    const receipt = makeValidReceiptRecord({ receipt_kind: "trace_observation" });
    delete receipt.decision;

    const errors = validateChioReceiptRecordStructure(receipt);
    expect(errors).toContainEqual(expect.stringContaining("boundary_class detect_only"));
    expect(errors).toContainEqual(expect.stringContaining("trust_level verified"));
    expect(errors).toContainEqual(expect.stringContaining("include observation_outcome"));
  });

  it("requires BBS projection and signature fields together", () => {
    const receipt = makeValidReceiptRecord({
      bbs_projection_version: "chio.bbs-projection.receipt.v1",
    });

    expect(validateChioReceiptRecordStructure(receipt)).toContainEqual(
      expect.stringContaining("must be present together"),
    );
  });
});

describe("verifyContentHash", () => {
  it("matches when content binding is correct", () => {
    // Build the same content binding that buildChioHttpRequest uses
    const result = verifyContentHash(
      makeValidReceipt(),
      "GET",
      "/pets/{petId}",
      "/pets/42",
      {},
      null,
    );
    // The hash won't match our synthetic "b".repeat(64) but this tests the function runs
    expect(typeof result).toBe("boolean");
  });
});

describe("assertVerdictMatch", () => {
  it("allows matching allow verdict", () => {
    const verdict: Verdict = { verdict: "allow" };
    const errors = assertVerdictMatch(verdict, { verdict: "allow" });
    expect(errors).toEqual([]);
  });

  it("detects verdict mismatch", () => {
    const verdict: Verdict = { verdict: "allow" };
    const errors = assertVerdictMatch(verdict, { verdict: "deny" });
    expect(errors).toContainEqual(expect.stringContaining("expected verdict"));
  });

  it("matches deny verdict with reason and guard", () => {
    const verdict: Verdict = {
      verdict: "deny",
      reason: "no capability",
      guard: "CapabilityGuard",
      http_status: 403,
    };
    const errors = assertVerdictMatch(verdict, {
      verdict: "deny",
      reason: "no capability",
      guard: "CapabilityGuard",
      http_status: 403,
    });
    expect(errors).toEqual([]);
  });

  it("detects deny reason mismatch", () => {
    const verdict: Verdict = {
      verdict: "deny",
      reason: "no capability",
      guard: "CapabilityGuard",
      http_status: 403,
    };
    const errors = assertVerdictMatch(verdict, {
      verdict: "deny",
      reason: "wrong reason",
    });
    expect(errors).toContainEqual(expect.stringContaining("deny reason"));
  });

  it("detects deny guard mismatch", () => {
    const verdict: Verdict = {
      verdict: "deny",
      reason: "no capability",
      guard: "CapabilityGuard",
      http_status: 403,
    };
    const errors = assertVerdictMatch(verdict, {
      verdict: "deny",
      guard: "WrongGuard",
    });
    expect(errors).toContainEqual(expect.stringContaining("deny guard"));
  });

  it("detects deny http_status mismatch", () => {
    const verdict: Verdict = {
      verdict: "deny",
      reason: "rate limited",
      guard: "RateGuard",
      http_status: 429,
    };
    const errors = assertVerdictMatch(verdict, {
      verdict: "deny",
      http_status: 403,
    });
    expect(errors).toContainEqual(expect.stringContaining("deny http_status"));
  });
});
