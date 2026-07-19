import test from "node:test";
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ChioInvariantError,
  canonicalizeJsonString,
  capabilityBodyCanonicalJson,
  parseCapabilityJson,
  parseReceiptJson,
  parseSignedManifestJson,
  receiptBodyCanonicalJson,
  receiptSigningBodyCanonicalJson,
  sha256HexUtf8,
  signJsonStringEd25519,
  signUtf8MessageEd25519,
  signedManifestBodyCanonicalJson,
  verifyCapability,
  verifyJsonStringSignatureEd25519,
  verifyReceipt,
  verifyReceiptWithTrustedSigners,
  verifySignedManifest,
  verifyUtf8MessageEd25519,
} from "../src/index.ts";

const testDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(testDir, "../../../../");

async function readJson(relativePath: string): Promise<unknown> {
  const absolutePath = resolve(repoRoot, relativePath);
  const raw = await readFile(absolutePath, "utf8");
  return JSON.parse(raw);
}

const watermarkPayloadFields = [
  "application_id",
  "encoding",
  "expires_at_unix_ms",
  "issued_at_unix_ms",
  "key_id",
  "marker_ref",
  "sequence",
  "session_id",
  "source_receipt_id",
  "tenant_id",
  "tool_id",
] as const;

const watermarkNumericFields = [
  "expires_at_unix_ms",
  "issued_at_unix_ms",
  "sequence",
] as const;

const declassificationEnvelopeFields = [
  "algorithm",
  "authority_key",
  "body",
  "signature",
] as const;

const declassificationBodyFields = [
  "agent_id",
  "authority_key_id",
  "capability_id",
  "destination_id",
  "domain_version",
  "expires_at_unix_seconds",
  "grant_id",
  "issued_at_unix_seconds",
  "purpose",
  "request_hash",
  "session_id",
  "source_label_hash",
  "subject_id",
  "target_label",
  "tenant_id",
  "tool_name",
] as const;

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
  receipt.signature = signJsonStringEd25519(
    receiptSigningBodyCanonicalJson(receipt),
    fixture.signing_key_seed_hex,
  ).signature_hex;

  const verification = verifyReceipt(receipt);

  assert.equal(verification.receipt_id_valid, false);
  assert.equal(verification.signature_valid, false);
  assert.equal(verification.ok, false);
});

test("signing vectors match the TS signing helpers", async () => {
  const fixture = await readJson("tests/bindings/vectors/signing/v1.json") as {
    signing_key_seed_hex: string;
    utf8_cases: Array<{
      id: string;
      input_utf8: string;
      public_key_hex: string;
      signature_hex: string;
      expected_verify: boolean;
      signing_key_seed_hex?: string;
    }>;
    json_cases: Array<{
      id: string;
      input_json: string;
      canonical_json: string;
      public_key_hex: string;
      signature_hex: string;
      expected_verify: boolean;
      signing_key_seed_hex?: string;
    }>;
  };

  for (const vectorCase of fixture.utf8_cases) {
    const seedHex = vectorCase.signing_key_seed_hex ?? fixture.signing_key_seed_hex;
    if (vectorCase.expected_verify) {
      assert.deepEqual(
        signUtf8MessageEd25519(vectorCase.input_utf8, seedHex),
        {
          public_key_hex: vectorCase.public_key_hex,
          signature_hex: vectorCase.signature_hex,
        },
        vectorCase.id,
      );
    }

    assert.equal(
      verifyUtf8MessageEd25519(
        vectorCase.input_utf8,
        vectorCase.public_key_hex,
        vectorCase.signature_hex,
      ),
      vectorCase.expected_verify,
      vectorCase.id,
    );
  }

  for (const vectorCase of fixture.json_cases) {
    const seedHex = vectorCase.signing_key_seed_hex ?? fixture.signing_key_seed_hex;
    assert.equal(canonicalizeJsonString(vectorCase.input_json), vectorCase.canonical_json, vectorCase.id);

    if (vectorCase.expected_verify) {
      assert.deepEqual(
        signJsonStringEd25519(vectorCase.input_json, seedHex),
        {
          canonical_json: vectorCase.canonical_json,
          public_key_hex: vectorCase.public_key_hex,
          signature_hex: vectorCase.signature_hex,
        },
        vectorCase.id,
      );
    }

    assert.equal(
      verifyJsonStringSignatureEd25519(
        vectorCase.input_json,
        vectorCase.public_key_hex,
        vectorCase.signature_hex,
      ),
      vectorCase.expected_verify,
      vectorCase.id,
    );
  }
});

test("declassification vector pins canonical domain-separated signature bytes in TS", async () => {
  const fixture = await readJson("tests/bindings/vectors/declassification/v1.json") as {
    positive: {
      id: string;
      signing_seed_hex: string;
      canonical_body_json: string;
      grant: {
        algorithm: string;
        authority_key: string;
        body: Record<string, unknown>;
        signature: string;
      };
    };
  };
  const vectorCase = fixture.positive;
  assert.deepEqual(Object.keys(vectorCase.grant).sort(), [...declassificationEnvelopeFields]);
  assert.deepEqual(Object.keys(vectorCase.grant.body).sort(), [...declassificationBodyFields]);
  assert.equal(vectorCase.grant.algorithm, "ed25519");
  const canonicalBody = canonicalizeJsonString(JSON.stringify(vectorCase.grant.body));
  assert.equal(canonicalBody, vectorCase.canonical_body_json, vectorCase.id);
  const signingMessage = `chio:declassification-grant:v1\0${canonicalBody}`;
  assert.deepEqual(
    signUtf8MessageEd25519(signingMessage, vectorCase.signing_seed_hex),
    {
      public_key_hex: vectorCase.grant.authority_key,
      signature_hex: vectorCase.grant.signature,
    },
    vectorCase.id,
  );
  assert.equal(
    verifyUtf8MessageEd25519(
      signingMessage,
      vectorCase.grant.authority_key,
      vectorCase.grant.signature,
    ),
    true,
    vectorCase.id,
  );
  assert.equal(
    verifyUtf8MessageEd25519(
      canonicalBody,
      vectorCase.grant.authority_key,
      vectorCase.grant.signature,
    ),
    false,
    `${vectorCase.id}:domain-separation`,
  );
});

test("signed watermark vectors pin canonical bytes and Ed25519 verification in TS", async () => {
  const fixture = await readJson(
    "crates/tooling/chio-conformance/vectors/security/watermark/v1.json",
  ) as {
    signing_domain: string;
    signing_key_seed_hex: string;
    cases: Array<{
      id: string;
      payload: Record<string, unknown>;
      canonical_payload_json: string;
      signing_message_hex: string;
      encoded_payload: string;
      public_key_hex: string;
      signature_hex: string;
      envelope: {
        schema: string;
        payload: Record<string, unknown>;
        encoded_payload: string;
        signature: string;
      };
      canonical_envelope_json: string;
      token: string;
    }>;
  };

  assert.equal(fixture.signing_domain, "chio.signed-watermark.v1\0");
  for (const vectorCase of fixture.cases) {
    assert.deepEqual(Object.keys(vectorCase.payload).sort(), [...watermarkPayloadFields], vectorCase.id);
    assert.equal(vectorCase.payload.encoding, "base64_url_canonical_json", vectorCase.id);
    for (const field of watermarkNumericFields) {
      const value = vectorCase.payload[field];
      if (typeof value !== "number") {
        assert.fail(`${vectorCase.id}:${field} must be a number`);
      }
      assert.equal(Number.isSafeInteger(value), true, `${vectorCase.id}:${field}`);
    }
    assert.equal(vectorCase.payload.sequence, Number.MAX_SAFE_INTEGER, vectorCase.id);

    const canonicalPayload = canonicalizeJsonString(JSON.stringify(vectorCase.payload));
    assert.equal(canonicalPayload, vectorCase.canonical_payload_json, vectorCase.id);
    const signingMessage = `${fixture.signing_domain}${canonicalPayload}`;
    assert.equal(Buffer.from(signingMessage, "utf8").toString("hex"), vectorCase.signing_message_hex);
    assert.deepEqual(
      signUtf8MessageEd25519(signingMessage, fixture.signing_key_seed_hex),
      {
        public_key_hex: vectorCase.public_key_hex,
        signature_hex: vectorCase.signature_hex,
      },
      vectorCase.id,
    );
    assert.equal(
      verifyUtf8MessageEd25519(signingMessage, vectorCase.public_key_hex, vectorCase.signature_hex),
      true,
      vectorCase.id,
    );
    assert.equal(
      verifyUtf8MessageEd25519(canonicalPayload, vectorCase.public_key_hex, vectorCase.signature_hex),
      false,
      `${vectorCase.id}:domain-separation`,
    );

    assert.equal(vectorCase.encoded_payload.includes("="), false, vectorCase.id);
    assert.equal(
      Buffer.from(canonicalPayload, "utf8").toString("base64url"),
      vectorCase.encoded_payload,
      vectorCase.id,
    );
    const decodedPayload = Buffer.from(vectorCase.encoded_payload, "base64url").toString("utf8");
    assert.equal(decodedPayload, canonicalPayload, vectorCase.id);
    assert.equal(Buffer.from(decodedPayload, "utf8").toString("base64url"), vectorCase.encoded_payload);

    assert.deepEqual(
      Object.keys(vectorCase.envelope).sort(),
      ["encoded_payload", "payload", "schema", "signature"],
      vectorCase.id,
    );
    assert.equal(vectorCase.envelope.schema, "chio.signed-watermark-envelope.v1", vectorCase.id);
    assert.deepEqual(vectorCase.envelope.payload, vectorCase.payload, vectorCase.id);
    assert.equal(vectorCase.envelope.encoded_payload, vectorCase.encoded_payload, vectorCase.id);
    assert.equal(vectorCase.envelope.signature, vectorCase.signature_hex, vectorCase.id);
    const canonicalEnvelope = canonicalizeJsonString(JSON.stringify(vectorCase.envelope));
    assert.equal(canonicalEnvelope, vectorCase.canonical_envelope_json, vectorCase.id);

    const tokenMatch = /^\[\[chio-wm1:([A-Za-z0-9_-]+)\]\]$/.exec(vectorCase.token);
    assert.ok(tokenMatch, vectorCase.id);
    const encodedEnvelope = tokenMatch[1];
    assert.ok(encodedEnvelope, vectorCase.id);
    const decodedEnvelope = Buffer.from(encodedEnvelope, "base64url").toString("utf8");
    assert.equal(decodedEnvelope, canonicalEnvelope, vectorCase.id);
    assert.equal(Buffer.from(decodedEnvelope, "utf8").toString("base64url"), encodedEnvelope);
    assert.deepEqual(JSON.parse(decodedEnvelope), vectorCase.envelope, vectorCase.id);
  }
});

test("signed watermark vectors reject integers at two to the fifty-third in TS", async () => {
  const fixture = await readJson(
    "crates/tooling/chio-conformance/vectors/security/watermark/v1-rejections.json",
  ) as {
    cases: Array<{
      id: string;
      input_payload_json: string;
      canonical_payload_json: string;
      field: string;
      value_decimal: string;
      expected_error: string;
    }>;
  };

  for (const vectorCase of fixture.cases) {
    assert.equal(
      canonicalizeJsonString(vectorCase.input_payload_json),
      vectorCase.canonical_payload_json,
      vectorCase.id,
    );
    const payload = JSON.parse(vectorCase.input_payload_json) as Record<string, unknown>;
    assert.deepEqual(Object.keys(payload).sort(), [...watermarkPayloadFields], vectorCase.id);
    const value = payload[vectorCase.field];
    if (typeof value !== "number") {
      assert.fail(`${vectorCase.id}:${vectorCase.field} must be a number`);
    }
    assert.equal(value, Number(vectorCase.value_decimal), vectorCase.id);
    assert.equal(Number.isSafeInteger(value), false, vectorCase.expected_error);
    assert.equal(value, 2 ** 53, vectorCase.id);
  }
});

test("capability vectors match the TS capability helpers", async () => {
  const fixture = await readJson("tests/bindings/vectors/capability/v1.json") as {
    cases: Array<{
      id: string;
      verify_at: number;
      capability: unknown;
      capability_body_canonical_json: string;
      expected: unknown;
      max_delegation_depth?: number;
      expected_with_max_delegation_depth?: unknown;
    }>;
  };

  for (const vectorCase of fixture.cases) {
    const capability = parseCapabilityJson(JSON.stringify(vectorCase.capability));
    assert.equal(
      capabilityBodyCanonicalJson(capability),
      vectorCase.capability_body_canonical_json,
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

test("manifest vectors match the TS manifest helpers", async () => {
  for (const version of ["v1", "v2"]) {
    const fixture = await readJson(`tests/bindings/vectors/manifest/${version}.json`) as {
      cases: Array<{
        id: string;
        signed_manifest: unknown;
        manifest_body_canonical_json: string;
        expected: unknown;
      }>;
    };

    for (const vectorCase of fixture.cases) {
      const signedManifest = parseSignedManifestJson(JSON.stringify(vectorCase.signed_manifest));
      assert.equal(
        signedManifestBodyCanonicalJson(signedManifest),
        vectorCase.manifest_body_canonical_json,
        `${version}:${vectorCase.id}`,
      );
      assert.deepEqual(
        verifySignedManifest(signedManifest),
        vectorCase.expected,
        `${version}:${vectorCase.id}`,
      );
    }
  }
});

test("manifest v2 canonical rejection vectors are rejected", async () => {
  const fixture = await readJson("tests/bindings/vectors/manifest/v2.json") as {
    cases: Array<{ id: string; signed_manifest: Record<string, any> }>;
  };
  const vectors = await readJson("tests/bindings/vectors/manifest/v2-canonical-rejections.json") as {
    cases: Array<{ id: string; field: string; replacement: unknown }>;
  };
  const baseline = fixture.cases.find((item) => item.id === "valid_signed_manifest");
  assert.ok(baseline, "valid v2 manifest vector must exist");
  for (const vectorCase of vectors.cases) {
    const envelope = structuredClone(baseline.signed_manifest);
    const permissions = envelope.manifest.required_permissions;
    const field = vectorCase.field.split(".");
    if (field.join(".") === "network_destinations.0.host") {
      permissions.network_destinations[0].host = vectorCase.replacement;
    } else if (field.join(".") === "read_paths.0") {
      permissions.read_paths[0] = vectorCase.replacement;
    } else {
      permissions[field[0]] = vectorCase.replacement;
    }
    const parsed = parseSignedManifestJson(JSON.stringify(envelope));
    assert.equal(verifySignedManifest(parsed).structure_valid, false, vectorCase.id);
  }
});
