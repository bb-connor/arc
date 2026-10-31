import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ChioInvariantError,
  canonicalizeJson,
  canonicalizeJsonString,
  capabilitySigningBodyCanonicalJson,
  parseCapabilityJson,
  parseReceiptJson,
  receiptBodyCanonicalJson,
  receiptSigningBodyCanonicalJson,
  publicKeyFromSeedEd25519,
  sha256HexUtf8,
  signWrappedJsonEd25519,
  verifyCapability,
  verifyReceipt,
  verifyReceiptWithTrustedSigners,
  verifyWrappedJson,
} from "../src/index.ts";

const testDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(testDir, "../../../../");

async function readJson(relativePath: string): Promise<unknown> {
  const absolutePath = resolve(repoRoot, relativePath);
  const raw = await readFile(absolutePath, "utf8");
  return JSON.parse(raw);
}

test("canonical vectors round-trip through the TS invariant helper", async () => {
  const fixture = await readJson("tests/bindings/vectors/canonical/v1.json") as {
    cases: Array<{
      id: string;
      input_json: string;
      canonical_json: string;
    }>;
  };

  for (const vectorCase of fixture.cases) {
    assert.equal(
      canonicalizeJsonString(vectorCase.input_json),
      vectorCase.canonical_json,
      vectorCase.id,
    );
  }
});

test("canonical strings pass DEL and C1 controls through per RFC 8785", () => {
  const controls = "\u007f\u009f";
  assert.equal(canonicalizeJson(controls), `"${controls}"`);
  assert.equal(canonicalizeJson({ [controls]: controls }), `{"${controls}":"${controls}"}`);
  assert.equal(
    canonicalizeJsonString('{"\\u007f\\u009f":"\\u007f\\u009f"}'),
    `{"${controls}":"${controls}"}`,
  );
});

test("canonical JSON rejects duplicate object keys", () => {
  assert.throws(
    () => canonicalizeJsonString('{"scope":"read","scope":"write"}'),
    (error) => error instanceof ChioInvariantError && /duplicate object key/.test(error.message),
  );
});

test("hashing vectors round-trip through the TS invariant helpers", async () => {
  const fixture = await readJson("tests/bindings/vectors/hashing/v1.json") as {
    cases: Array<{
      id: string;
      input_utf8: string;
      sha256_hex: string;
    }>;
  };

  for (const vectorCase of fixture.cases) {
    assert.equal(sha256HexUtf8(vectorCase.input_utf8), vectorCase.sha256_hex, vectorCase.id);
  }
});

test("receipt vectors match the TS receipt helpers", async () => {
  const fixture = await readJson("tests/bindings/vectors/receipt/v1.json") as {
    cases: Array<{
      id: string;
      receipt: unknown;
      receipt_body_canonical_json: string;
      expected: unknown;
    }>;
  };

  for (const vectorCase of fixture.cases) {
    const receipt = parseReceiptJson(JSON.stringify(vectorCase.receipt));
    assert.equal(receiptBodyCanonicalJson(receipt), vectorCase.receipt_body_canonical_json, vectorCase.id);
    assert.deepEqual(verifyReceipt(receipt), vectorCase.expected, vectorCase.id);
  }
});

test("receipt vectors support trusted signer verification in TS", async () => {
  const fixture = await readJson("tests/bindings/vectors/receipt/v1.json") as {
    cases: Array<{
      id: string;
      receipt: { kernel_key: string };
    }>;
  };
  const vectorCase = fixture.cases.find((item) => item.id === "allow_receipt");
  assert.ok(vectorCase, "allow receipt vector must exist");

  const verification = verifyReceiptWithTrustedSigners(vectorCase.receipt, [vectorCase.receipt.kernel_key]);

  assert.equal(verification.signer_trusted, true);
  assert.equal(verification.ok, true);
  assert.equal(verification.authorized, true);
});

test("TS receipt semantics ignore legacy metadata payloads", async () => {
  const fixture = await readJson("tests/bindings/vectors/receipt/v1.json") as {
    cases: Array<{
      id: string;
      receipt: unknown;
    }>;
  };
  const vectorCase = fixture.cases.find((item) => item.id === "allow_receipt");
  assert.ok(vectorCase, "allow receipt vector must exist");
  const receipt = JSON.parse(JSON.stringify(vectorCase.receipt));
  receipt.metadata = {
    receipt_semantics: {
      receiptKind: "trace_observation",
      boundaryClass: "detect_only",
    },
  };

  const verification = verifyReceiptWithTrustedSigners(receipt, [receipt.kernel_key]);

  assert.equal(verification.receipt_kind, "mediated_decision");
  assert.equal(verification.boundary_class, "prevent");
  assert.equal(verification.receipt_id_valid, false);
  assert.equal(verification.signature_valid, false);
  assert.equal(verification.authorized, false);
});

test("TS receipt signature validity fails when the content-addressed id mismatches", async () => {
  const fixture = await readJson("tests/bindings/vectors/receipt/v1.json") as {
    signing_key_seed_hex: string;
    cases: Array<{
      id: string;
      receipt: { id: string; kernel_key: string; signature: string };
    }>;
  };
  const vectorCase = fixture.cases.find((item) => item.id === "allow_receipt");
  assert.ok(vectorCase, "allow receipt vector must exist");
  const receipt = JSON.parse(JSON.stringify(vectorCase.receipt));
  receipt.id = "0000000000000000000000000000000000000000000000000000000000000000";
  receipt.signature = signWrappedJsonEd25519(
    "chio.receipt.v1",
    receiptSigningBodyCanonicalJson(receipt),
    fixture.signing_key_seed_hex,
  ).signature_hex;

  const verification = verifyReceipt(receipt);

  assert.equal(verification.receipt_id_valid, false);
  assert.equal(verification.signature_valid, false);
  assert.equal(verification.ok, false);
});

function wrappedVerifies(schemaId: string, input: string, publicKey: string, signature: string): boolean {
  try {
    verifyWrappedJson(schemaId, input, publicKey, signature);
    return true;
  } catch (error) {
    if (error instanceof ChioInvariantError) {
      return false;
    }
    throw error;
  }
}

test("signing vectors match the TS wrapped signing helpers", async (t) => {
  const fixture = await readJson("tests/bindings/vectors/signing/v1.json") as {
    signing_key_seed_hex: string;
    utf8_cases?: unknown[];
    json_cases: Array<{
      id: string;
      schema_id?: string;
      input_json: string;
      canonical_json: string;
      public_key_hex: string;
      signature_hex: string;
      expected_verify: boolean;
      signing_key_seed_hex?: string;
    }>;
  };
  if (fixture.json_cases.some((vectorCase) => vectorCase.schema_id === undefined)) {
    t.skip("signing vectors carry no schema_id until they regenerate");
    return;
  }
  assert.equal(fixture.utf8_cases, undefined);

  for (const vectorCase of fixture.json_cases) {
    const schemaId = vectorCase.schema_id as string;
    const seedHex = vectorCase.signing_key_seed_hex ?? fixture.signing_key_seed_hex;
    assert.equal(canonicalizeJsonString(vectorCase.input_json), vectorCase.canonical_json, vectorCase.id);
    if (vectorCase.expected_verify) {
      assert.deepEqual(
        signWrappedJsonEd25519(schemaId, vectorCase.input_json, seedHex),
        {
          schema_id: schemaId,
          canonical_json: vectorCase.canonical_json,
          public_key_hex: vectorCase.public_key_hex,
          signature_hex: vectorCase.signature_hex,
        },
        vectorCase.id,
      );
    }
    assert.equal(
      wrappedVerifies(schemaId, vectorCase.input_json, vectorCase.public_key_hex, vectorCase.signature_hex),
      vectorCase.expected_verify,
      vectorCase.id,
    );
  }
});

test("wrapped signer derives the seed identity and refuses unregistered ids", () => {
  const seed = "01".repeat(32);
  const signed = signWrappedJsonEd25519("chio.receipt.v1", '{"b":1,"a":2}', seed);
  assert.equal(signed.public_key_hex, publicKeyFromSeedEd25519(seed));
  assert.equal(signed.canonical_json, '{"a":2,"b":1}');
  verifyWrappedJson("chio.receipt.v1", '{"a":2,"b":1}', signed.public_key_hex, signed.signature_hex);
  assert.throws(
    () => signWrappedJsonEd25519("chio.unregistered-fixture.v1", "{}", seed),
    (error: unknown) =>
      error instanceof ChioInvariantError &&
      error.code === "unregistered_schema_id" &&
      error.message === "unregistered signed-artifact schema id: chio.unregistered-fixture.v1",
  );
  assert.throws(
    () => verifyWrappedJson("chio.capability.v1", '{"a":2,"b":1}', signed.public_key_hex, signed.signature_hex),
    (error: unknown) =>
      error instanceof ChioInvariantError && error.code === "signature_rejected" && error.message === "signature rejected",
  );
});

test("capability with an algorithm member is refused", async () => {
  const fixture = await readJson("tests/bindings/vectors/capability/v1.json") as {
    cases: Array<{ capability: Record<string, unknown> }>;
  };
  for (const algorithm of ["ed25519", "p256"]) {
    const capability = { ...fixture.cases[0].capability, algorithm };
    assert.throws(
      () => parseCapabilityJson(JSON.stringify(capability)),
      (error: unknown) =>
        error instanceof ChioInvariantError &&
        error.code === "json" &&
        error.message === "capability has unknown member algorithm",
    );
  }
});

const ROOT_ANCHOR = {
  kind: "oidc_jwt",
  context_digest: `sha256:${"a".repeat(64)}`,
  root_policy_digest: `sha256:${"b".repeat(64)}`,
  anchored_at: 1700000000,
  assertion_exp: 1700000600,
};

async function anchoredCapabilityJson(anchor: unknown): Promise<string> {
  const fixture = await readJson("tests/bindings/vectors/capability/v1.json") as {
    cases: Array<{ capability: Record<string, unknown> }>;
  };
  return JSON.stringify({ ...fixture.cases[0].capability, root_anchor: anchor });
}

test("root_anchor decodes every kind and enters the signing body", async () => {
  for (const kind of [
    "oauth_id_jag",
    "entra_jwt",
    "entra_agent_id",
    "oidc_jwt",
    "oauth_introspection",
    "chio_local_as",
    "chio_operator_key",
    "operator_static_bearer",
  ]) {
    const capability = parseCapabilityJson(await anchoredCapabilityJson({ ...ROOT_ANCHOR, kind }));
    const expected =
      `"root_anchor":{"anchored_at":1700000000,"assertion_exp":1700000600,` +
      `"context_digest":"${ROOT_ANCHOR.context_digest}","kind":"${kind}",` +
      `"root_policy_digest":"${ROOT_ANCHOR.root_policy_digest}"}`;
    assert.ok(capabilitySigningBodyCanonicalJson(capability).includes(expected), kind);
  }
});

test("root_anchor refuses malformed values", async () => {
  const { kind: _kind, ...withoutKind } = ROOT_ANCHOR;
  const { assertion_exp: _exp, ...withoutExp } = ROOT_ANCHOR;
  const cases: Array<[unknown, string]> = [
    ["oidc_jwt", "root_anchor must be a JSON object"],
    [{ ...ROOT_ANCHOR, padding: "x" }, "root_anchor has unknown member padding"],
    [withoutKind, "root_anchor is missing member kind"],
    [withoutExp, "root_anchor is missing member assertion_exp"],
    [{ ...ROOT_ANCHOR, kind: "spiffe" }, "root_anchor kind is not a known anchor kind"],
    [{ ...ROOT_ANCHOR, kind: 1 }, "root_anchor kind is not a known anchor kind"],
    [
      { ...ROOT_ANCHOR, context_digest: `sha256:${"A".repeat(64)}` },
      "root_anchor context_digest must be a sha256 digest",
    ],
    [
      { ...ROOT_ANCHOR, root_policy_digest: "b".repeat(64) },
      "root_anchor root_policy_digest must be a sha256 digest",
    ],
    [{ ...ROOT_ANCHOR, anchored_at: -1 }, "root_anchor anchored_at must be an unsigned integer"],
    [
      { ...ROOT_ANCHOR, assertion_exp: "1700000600" },
      "root_anchor assertion_exp must be an unsigned integer",
    ],
    [
      { ...ROOT_ANCHOR, assertion_exp: 9007199254740992 },
      "root_anchor assertion_exp must be an unsigned integer",
    ],
  ];
  for (const [anchor, message] of cases) {
    const input = await anchoredCapabilityJson(anchor);
    assert.throws(
      () => parseCapabilityJson(input),
      (error: unknown) =>
        error instanceof ChioInvariantError && error.code === "json" && error.message === message,
    );
  }
});

test("signing wrapper vectors verify as expected", async () => {
  const fixture = await readJson("tests/bindings/vectors/signing/wrapper/v1.json") as {
    signature_cases: Array<{
      id: string;
      algorithm: string;
      canonical_body: string;
      public_key: string;
      signature: string;
      verify_schema_id: string;
      expected_verify: boolean;
    }>;
  };
  for (const vectorCase of fixture.signature_cases) {
    assert.equal(
      wrappedVerifies(vectorCase.verify_schema_id, vectorCase.canonical_body, vectorCase.public_key, vectorCase.signature),
      vectorCase.expected_verify,
      vectorCase.id,
    );
  }
});

test("capability vectors match the TS capability helpers", async () => {
  const fixture = await readJson("tests/bindings/vectors/capability/v1.json") as {
    cases: Array<{
      id: string;
      verify_at: number;
      capability: unknown;
      capability_signing_body_canonical_json: string;
      expected: unknown;
      max_delegation_depth?: number;
      expected_with_max_delegation_depth?: unknown;
    }>;
  };

  for (const vectorCase of fixture.cases) {
    const capability = parseCapabilityJson(JSON.stringify(vectorCase.capability));
    assert.equal(
      capabilitySigningBodyCanonicalJson(capability),
      vectorCase.capability_signing_body_canonical_json,
      vectorCase.id,
    );
    assert.deepEqual(
      verifyCapability(capability, vectorCase.verify_at),
      vectorCase.expected,
      `${vectorCase.id} (no max depth)`,
    );
    if (vectorCase.max_delegation_depth !== undefined) {
      assert.deepEqual(
        verifyCapability(capability, vectorCase.verify_at, vectorCase.max_delegation_depth),
        vectorCase.expected_with_max_delegation_depth ?? vectorCase.expected,
        `${vectorCase.id} (max_delegation_depth=${vectorCase.max_delegation_depth})`,
      );
    }
  }
});

test("capability parser rejects non-object JSON", () => {
  for (const payload of ["null", "[]", "\"capability\"", "42"]) {
    assert.throws(
      () => parseCapabilityJson(payload),
      (error: unknown) =>
        error instanceof ChioInvariantError &&
        error.code === "json" &&
        error.message === "capability must be a JSON object",
      payload,
    );
  }
});

test("capability parser rejects a token without the v1 schema", () => {
  for (const payload of [
    '{"id":"cap"}',
    '{"id":"cap","schema":"chio.capability.v2"}',
  ]) {
    assert.throws(
      () => parseCapabilityJson(payload),
      (error: unknown) =>
        error instanceof ChioInvariantError &&
        error.code === "json" &&
        error.message === 'capability schema must be "chio.capability.v1"',
      payload,
    );
  }
});
