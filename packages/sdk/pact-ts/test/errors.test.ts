import test from "node:test";
import assert from "node:assert/strict";

import {
  canonicalizeJson,
  canonicalizeJsonString,
  PactInvariantError,
  signUtf8MessageEd25519,
  verifyUtf8MessageEd25519,
} from "../src/index.ts";

import {
  PactError,
  DpopSignError,
  QueryError,
  TransportError,
} from "../src/errors.ts";

// --- Existing invariant error tests ---

test("invalid JSON surfaces a stable pact invariant error", () => {
  assert.throws(
    () => canonicalizeJsonString("{"),
    (error: unknown) =>
      error instanceof PactInvariantError &&
      error.code === "json" &&
      error.message === "input is not valid JSON",
  );
});

test("unsupported canonical JSON values surface a stable code", () => {
  assert.throws(
    () => canonicalizeJson(undefined),
    (error: unknown) =>
      error instanceof PactInvariantError &&
      error.code === "canonical_json",
  );
});

test("invalid signing seed surfaces a stable code", () => {
  assert.throws(
    () => signUtf8MessageEd25519("hello", "zz"),
    (error: unknown) =>
      error instanceof PactInvariantError &&
      error.code === "invalid_hex",
  );
});

test("malformed public keys are errors, not false verifications", () => {
  assert.throws(
    () => verifyUtf8MessageEd25519("hello", "abcd", "00".repeat(64)),
    (error: unknown) =>
      error instanceof PactInvariantError &&
      error.code === "invalid_public_key",
  );
});

// --- New SDK-level error hierarchy tests ---

test("PactError has name PactError, a code property, and extends Error", () => {
  const err = new PactError("some_code", "some message");
  assert.equal(err.name, "PactError");
  assert.equal(err.code, "some_code");
  assert.equal(err.message, "some message");
  assert.ok(err instanceof Error);
  assert.ok(err instanceof PactError);
});

test("PactError supports ErrorOptions cause", () => {
  const cause = new Error("root cause");
  const err = new PactError("some_code", "wrapper", { cause });
  assert.equal(err.cause, cause);
});

test("DpopSignError has name DpopSignError, code dpop_sign_error, and is instanceof PactError", () => {
  const err = new DpopSignError("failed to sign");
  assert.equal(err.name, "DpopSignError");
  assert.equal(err.code, "dpop_sign_error");
  assert.equal(err.message, "failed to sign");
  assert.ok(err instanceof Error);
  assert.ok(err instanceof PactError);
  assert.ok(err instanceof DpopSignError);
});

test("DpopSignError supports ErrorOptions cause", () => {
  const cause = new Error("crypto failure");
  const err = new DpopSignError("sign error", { cause });
  assert.equal(err.cause, cause);
});

test("QueryError has name QueryError, code query_error, optional status, and is instanceof PactError", () => {
  const errNoStatus = new QueryError("query failed");
  assert.equal(errNoStatus.name, "QueryError");
  assert.equal(errNoStatus.code, "query_error");
  assert.equal(errNoStatus.message, "query failed");
  assert.equal(errNoStatus.status, undefined);
  assert.ok(errNoStatus instanceof PactError);

  const errWithStatus = new QueryError("not found", 404);
  assert.equal(errWithStatus.status, 404);
  assert.ok(errWithStatus instanceof PactError);
  assert.ok(errWithStatus instanceof QueryError);
});

test("QueryError supports ErrorOptions cause", () => {
  const cause = new Error("network issue");
  const err = new QueryError("query failed", undefined, { cause });
  assert.equal(err.cause, cause);
});

test("TransportError has name TransportError, code transport_error, and is instanceof PactError", () => {
  const err = new TransportError("connection refused");
  assert.equal(err.name, "TransportError");
  assert.equal(err.code, "transport_error");
  assert.equal(err.message, "connection refused");
  assert.ok(err instanceof Error);
  assert.ok(err instanceof PactError);
  assert.ok(err instanceof TransportError);
});

test("TransportError supports ErrorOptions cause", () => {
  const cause = new Error("ECONNREFUSED");
  const err = new TransportError("transport failed", { cause });
  assert.equal(err.cause, cause);
});

test("all SDK error subclasses are instanceof PactError", () => {
  const errors: PactError[] = [
    new DpopSignError("dpop"),
    new QueryError("query"),
    new TransportError("transport"),
  ];
  for (const err of errors) {
    assert.ok(err instanceof PactError, `${err.name} should be instanceof PactError`);
  }
});
