import test from "node:test";
import assert from "node:assert/strict";

import { verifySignedManifest } from "../src/index.ts";
import type { SignedManifest } from "../src/index.ts";

function pricedSignedManifest(): SignedManifest {
  return {
    manifest: {
      schema: "chio.manifest.v1",
      server_id: "srv-priced",
      name: "Priced Server",
      version: "1.0.0",
      tools: [
        {
          name: "greet",
          description: "Returns a greeting",
          input_schema: { type: "object" },
          pricing: {
            pricing_model: "per_invocation",
            unit_price: { units: 25, currency: "USD" },
            billing_unit: "invocation",
          },
          has_side_effects: false,
          latency_hint: "instant",
        },
      ],
      public_key: "22".repeat(32),
    },
    signature: "33".repeat(64),
    signer_key: "11".repeat(32),
  };
}

test("signed manifest typing and verification preserve pricing metadata", () => {
  const signedManifest = pricedSignedManifest();

  assert.equal(
    signedManifest.manifest.tools[0].pricing?.unit_price?.units,
    25,
  );

  const verification = verifySignedManifest(signedManifest);
  assert.equal(verification.structure_valid, true);
  assert.equal(verification.signature_valid, false);
  assert.equal(verification.embedded_public_key_valid, true);
  assert.equal(verification.embedded_public_key_matches_signer, false);
});

test("manifest structure does not include embedded public key validity", () => {
  const signedManifest = pricedSignedManifest();
  signedManifest.manifest.public_key = "demo-placeholder";

  const verification = verifySignedManifest(signedManifest);

  assert.equal(verification.structure_valid, true);
  assert.equal(verification.embedded_public_key_valid, false);
  assert.equal(verification.embedded_public_key_matches_signer, false);
});

test("manifest structure rejects empty or padded identity fields", () => {
  for (const [field, value] of [
    ["server_id", ""],
    ["server_id", " srv-priced"],
    ["server_id", "srv-priced "],
    ["name", ""],
    ["name", " Priced Server"],
    ["name", "Priced Server "],
    ["version", ""],
    ["version", " 1.0.0"],
    ["version", "1.0.0 "],
  ] as const) {
    const signedManifest = pricedSignedManifest();
    signedManifest.manifest[field] = value;

    const verification = verifySignedManifest(signedManifest);

    assert.equal(
      verification.structure_valid,
      false,
      `${field} ${JSON.stringify(value)}`,
    );
    assert.equal(verification.signature_valid, false);
    assert.equal(verification.embedded_public_key_valid, true);
  }
});

test("manifest structure rejects empty or padded tool names", () => {
  for (const name of ["", " greet", "greet "]) {
    const signedManifest = pricedSignedManifest();
    signedManifest.manifest.tools[0].name = name;

    const verification = verifySignedManifest(signedManifest);

    assert.equal(
      verification.structure_valid,
      false,
      `name ${JSON.stringify(name)}`,
    );
  }
});

test("manifest structure rejects non-object tool schemas", () => {
  const badInputSchema = pricedSignedManifest();
  badInputSchema.manifest.tools[0].input_schema = [];
  assert.equal(verifySignedManifest(badInputSchema).structure_valid, false);

  const badOutputSchema = pricedSignedManifest();
  badOutputSchema.manifest.tools[0].output_schema = "not an object";
  assert.equal(verifySignedManifest(badOutputSchema).structure_valid, false);
});

test("manifest structure rejects non-object tool entries", () => {
  const signedManifest = pricedSignedManifest();
  (signedManifest.manifest.tools as unknown[])[0] = null;

  assert.equal(verifySignedManifest(signedManifest).structure_valid, false);
});

test("manifest structure rejects malformed pricing metadata", () => {
  for (const [label, pricing] of [
    [
      "per_invocation missing unit_price",
      { pricing_model: "per_invocation", billing_unit: "invocation" },
    ],
    [
      "per_unit missing billing_unit",
      { pricing_model: "per_unit", unit_price: { units: 25, currency: "USD" } },
    ],
    [
      "hybrid missing base_price",
      {
        pricing_model: "hybrid",
        unit_price: { units: 25, currency: "USD" },
        billing_unit: "document",
      },
    ],
    [
      "padded billing_unit",
      {
        pricing_model: "per_invocation",
        unit_price: { units: 25, currency: "USD" },
        billing_unit: " invocation",
      },
    ],
    [
      "invalid currency",
      {
        pricing_model: "per_invocation",
        unit_price: { units: 25, currency: "usd" },
        billing_unit: "invocation",
      },
    ],
    [
      "units above u64 max",
      {
        pricing_model: "per_invocation",
        unit_price: { units: 2 ** 64, currency: "USD" },
        billing_unit: "invocation",
      },
    ],
  ] as const) {
    const signedManifest = pricedSignedManifest();
    (signedManifest.manifest.tools[0] as { pricing?: unknown }).pricing = pricing;

    assert.equal(
      verifySignedManifest(signedManifest).structure_valid,
      false,
      label,
    );
  }
});

test("manifest structure accepts Rust u64 pricing units above JS safe integer", () => {
  const signedManifest = pricedSignedManifest();
  const largeRustU64Units = Number.MAX_SAFE_INTEGER + 2;
  assert.equal(Number.isSafeInteger(largeRustU64Units), false);
  (signedManifest.manifest.tools[0] as { pricing?: { unit_price?: { units?: number } } })
    .pricing!.unit_price!.units = largeRustU64Units;

  assert.equal(verifySignedManifest(signedManifest).structure_valid, true);
});

test("signed manifest envelope rejects unknown top-level fields", () => {
  const signedManifest = pricedSignedManifest() as SignedManifest & {
    unsigned_policy_hint?: unknown;
  };
  signedManifest.unsigned_policy_hint = { allow: true };

  assert.equal(verifySignedManifest(signedManifest).structure_valid, false);
});

test("manifest structure accepts valid required permissions", () => {
  const signedManifest = pricedSignedManifest();
  signedManifest.manifest.required_permissions = {
    read_paths: ["/tmp/in"],
    write_paths: ["/tmp/out"],
    network_hosts: ["api.example.com"],
    environment_variables: ["TOKEN"],
  };

  const verification = verifySignedManifest(signedManifest);

  assert.equal(verification.structure_valid, true);
  assert.equal(verification.signature_valid, false);
  assert.equal(verification.embedded_public_key_valid, true);
});

test("manifest structure rejects invalid required permissions", () => {
  for (const [field, values] of [
    ["read_paths", [""]],
    ["write_paths", [" /tmp/out"]],
    ["network_hosts", ["api.example.com "]],
    ["environment_variables", ["TOKEN", "TOKEN"]],
    ["read_paths", [123]],
  ] as const) {
    const signedManifest = pricedSignedManifest();
    signedManifest.manifest.required_permissions = { [field]: values };

    const verification = verifySignedManifest(signedManifest);

    assert.equal(
      verification.structure_valid,
      false,
      `${field} ${JSON.stringify(values)}`,
    );
    assert.equal(verification.signature_valid, false);
    assert.equal(verification.embedded_public_key_valid, true);
  }
});

test("manifest structure rejects malformed required permissions object", () => {
  const unknownField = pricedSignedManifest();
  (unknownField.manifest as { required_permissions?: unknown }).required_permissions = {
    unknown: ["/tmp"],
  };
  assert.equal(verifySignedManifest(unknownField).structure_valid, false);

  const nonArrayValues = pricedSignedManifest();
  (nonArrayValues.manifest as { required_permissions?: unknown }).required_permissions = {
    read_paths: "/tmp",
  };
  assert.equal(verifySignedManifest(nonArrayValues).structure_valid, false);
});
