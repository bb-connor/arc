import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { signAuthorityDpopProof, signDpopProof, DPOP_AUTHORITY_SCHEMA } from "../src/dpop.ts";
import { DpopSignError } from "../src/errors.ts";
import { sha256Hex, verifyEd25519Signature } from "../src/invariants/crypto.ts";
import { canonicalizeJson } from "../src/invariants/json.ts";

const domain = {
  destination_store_uuid: "018f9878-7047-7abc-8c98-120dc65700ea",
  dpop_authority_id: "configured-dpop",
  expectation_id: "a".repeat(64), proof_ttl_secs: 300, max_clock_skew_secs: 30,
};
const params = {
  capabilityId: "capability", toolServer: "server", toolName: "tool", actionArgs: {},
  agentSeedHex: "a".repeat(64), nonce: "nonce", issuedAt: 1_800_000_000,
};

test("shared Rust and TypeScript wire vector stays byte-exact", () => {
  const vector = JSON.parse(readFileSync(new URL("../../../../tests/bindings/fixtures/dpop-authority-v2.json", import.meta.url), "utf8"));
  const proof = signAuthorityDpopProof({ ...params, replayAuthority: domain });
  assert.deepEqual(proof, vector.proof);
  assert.equal(canonicalizeJson(proof.body), vector.canonical_body);
  assert.equal(sha256Hex(canonicalizeJson(proof)), vector.proof_sha256);
});

test("v2 signs the exact domain without changing the v1 preimage", () => {
  const legacy = signDpopProof(params);
  assert.equal(Object.keys(legacy.body).length, 8);
  assert.equal("replay_authority" in legacy.body, false);
  const proof = signAuthorityDpopProof({ ...params, replayAuthority: domain });
  assert.equal(proof.body.schema, DPOP_AUTHORITY_SCHEMA);
  assert.deepEqual(proof.body.replay_authority, domain);
  assert.notEqual(proof.signature, legacy.signature);
  assert.ok(verifyEd25519Signature(canonicalizeJson(proof.body), proof.body.agent_key, proof.signature));
});

test("signed authority is detached from mutable caller configuration", () => {
  const input = { ...domain };
  const proof = signAuthorityDpopProof({ ...params, replayAuthority: input });
  input.proof_ttl_secs = 301;
  assert.deepEqual(proof.body.replay_authority, domain);
  assert.ok(verifyEd25519Signature(canonicalizeJson(proof.body), proof.body.agent_key, proof.signature));
});

test("every signed domain field detects tampering", () => {
  const proof = signAuthorityDpopProof({ ...params, replayAuthority: domain });
  for (const change of [
    { destination_store_uuid: "018f9878-7047-7abc-8c98-120dc65700eb" },
    { dpop_authority_id: "other" }, { expectation_id: "b".repeat(64) },
    { proof_ttl_secs: 301 }, { max_clock_skew_secs: 31 },
  ]) {
    const body = { ...proof.body, replay_authority: { ...domain, ...change } };
    assert.equal(verifyEd25519Signature(canonicalizeJson(body), body.agent_key, proof.signature), false);
  }
});

test("invalid or ambiguous domains and unsafe proof horizons are rejected", () => {
  for (const change of [
    { destination_store_uuid: domain.destination_store_uuid.toUpperCase() },
    { destination_store_uuid: "00000000-0000-0000-0000-000000000000" },
    { dpop_authority_id: " padded" }, { dpop_authority_id: "é".repeat(257) },
    { expectation_id: "not-a-digest" }, { proof_ttl_secs: 0 }, { proof_ttl_secs: 3601 },
    { proof_ttl_secs: 1.5 }, { max_clock_skew_secs: -1 }, { max_clock_skew_secs: 301 },
    { activated: true },
  ]) {
    assert.throws(() => signAuthorityDpopProof({ ...params, replayAuthority: { ...domain, ...change } }), DpopSignError);
  }
  for (const change of [{ nonce: "é".repeat(2049) }, { capabilityId: "x".repeat(4097) },
    { issuedAt: 9_007_199_254_740 }, { issuedAt: -1 }, { issuedAt: 1.5 }]) {
    assert.throws(() => signAuthorityDpopProof({ ...params, ...change, replayAuthority: domain }), DpopSignError);
  }
});

test("authority padding follows Unicode White_Space without normalizing names", () => {
  for (const name of ["\ufeffauthority", "authority\ufeff", "authority\u2000name"]) {
    const proof = signAuthorityDpopProof({ ...params, replayAuthority: { ...domain, dpop_authority_id: name } });
    assert.equal(proof.body.replay_authority?.dpop_authority_id, name);
    assert.ok(verifyEd25519Signature(canonicalizeJson(proof.body), proof.body.agent_key, proof.signature));
  }
  for (const padding of [" ", "\u0085", "\u00a0", "\u1680", "\u2000", "\u2001",
    "\u2002", "\u2003", "\u2004", "\u2005", "\u2006", "\u2007", "\u2008", "\u2009",
    "\u200a", "\u2028", "\u2029", "\u202f", "\u205f", "\u3000"]) {
    for (const name of [`${padding}authority`, `authority${padding}`]) {
      assert.throws(() => signAuthorityDpopProof({ ...params, replayAuthority: { ...domain, dpop_authority_id: name } }), DpopSignError);
    }
  }
});
