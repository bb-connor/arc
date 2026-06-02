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
