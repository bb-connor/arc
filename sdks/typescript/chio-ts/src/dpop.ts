import { randomBytes } from "node:crypto";

import { DpopSignError } from "./errors.ts";
import { signEd25519Message, sha256Hex } from "./invariants/crypto.ts";
import { canonicalizeJson } from "./invariants/json.ts";

/**
 * The schema identifier for DPoP proofs. Must match chio-kernel's DPOP_SCHEMA constant.
 */
export const DPOP_SCHEMA = "chio.dpop_proof.v1";
export const DPOP_AUTHORITY_SCHEMA = "chio.dpop_proof.v2";

/** Independently configured durable domain. This data does not prove activation. */
export interface DpopReplayAuthority {
  destination_store_uuid: string;
  dpop_authority_id: string;
  expectation_id: string;
  proof_ttl_secs: number;
  max_clock_skew_secs: number;
}

/**
 * The body of a DPoP proof. Field names use snake_case to match Rust/serde serialization.
 * Field order in canonical JSON is alphabetical (RFC 8785), which also matches serde's default.
 *
 * V1 fields (alphabetical order as they appear in canonical JSON):
 *   action_hash, agent_key, capability_id, issued_at, nonce, schema, tool_name, tool_server
 * V2 adds replay_authority between nonce and schema in the canonical preimage.
 */
export interface DpopProofBody {
  action_hash: string;
  agent_key: string;
  capability_id: string;
  issued_at: number;
  nonce: string;
  replay_authority?: DpopReplayAuthority;
  schema: string;
  tool_name: string;
  tool_server: string;
}

/**
 * A signed DPoP proof. The signature is Ed25519 over the canonical JSON of the body.
 */
export interface DpopProof {
  body: DpopProofBody;
  signature: string;
}

/**
 * Parameters for signDpopProof.
 */
export interface SignDpopProofParams {
  capabilityId: string;
  toolServer: string;
  toolName: string;
  actionArgs: unknown;
  agentSeedHex: string;
  nonce?: string;
  issuedAt?: number;
}

/**
 * Sign a DPoP proof for a Chio tool invocation.
 *
 * The proof body is serialized as RFC 8785 canonical JSON before signing,
 * ensuring compatibility with chio-kernel's verify_dpop_proof.
 *
 * @throws DpopSignError if the agentSeedHex is invalid or signing fails.
 */
export function signDpopProof(params: SignDpopProofParams): DpopProof {
  return signProof(params);
}

export interface SignAuthorityDpopProofParams extends SignDpopProofParams {
  replayAuthority: DpopReplayAuthority;
}

/**
 * Sign the explicit v2 durable profile. Obtain the domain through authenticated
 * configuration; a proof must not choose the verifier's authority. Legacy
 * nonce-store verifiers reject this profile. Signing does not reserve a nonce.
 */
export function signAuthorityDpopProof(params: SignAuthorityDpopProofParams): DpopProof {
  try {
    return signProof(params, copyAuthority(params.replayAuthority));
  } catch (cause) {
    if (cause instanceof DpopSignError) throw cause;
    throw new DpopSignError("invalid durable DPoP authority", { cause });
  }
}

function copyAuthority(input: DpopReplayAuthority): DpopReplayAuthority {
  const expected = ["destination_store_uuid", "dpop_authority_id", "expectation_id", "proof_ttl_secs", "max_clock_skew_secs"];
  if (typeof input !== "object" || input === null || Array.isArray(input)
    || Object.keys(input).length !== expected.length || expected.some((key) => !Object.hasOwn(input, key))) {
    throw new DpopSignError("durable DPoP authority must contain exactly its five fields");
  }
  const value = {
    destination_store_uuid: input.destination_store_uuid,
    dpop_authority_id: input.dpop_authority_id,
    expectation_id: input.expectation_id,
    proof_ttl_secs: input.proof_ttl_secs,
    max_clock_skew_secs: input.max_clock_skew_secs,
  };
  if (typeof value.destination_store_uuid !== "string"
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value.destination_store_uuid)
    || value.destination_store_uuid === "00000000-0000-0000-0000-000000000000"
    || typeof value.dpop_authority_id !== "string" || value.dpop_authority_id.length === 0
    // Match Rust's Unicode White_Space predicate. JavaScript trim also removes
    // U+FEFF, which is not padding in the Rust authority identifier profile.
    || /^\p{White_Space}|\p{White_Space}$/u.test(value.dpop_authority_id)
    || /[\u0000-\u001f\u007f-\u009f]/.test(value.dpop_authority_id)
    || Buffer.byteLength(value.dpop_authority_id, "utf8") > 512
    || typeof value.expectation_id !== "string" || !/^[0-9a-f]{64}$/.test(value.expectation_id)
    || !Number.isSafeInteger(value.proof_ttl_secs) || value.proof_ttl_secs < 1 || value.proof_ttl_secs > 3600
    || !Number.isSafeInteger(value.max_clock_skew_secs) || value.max_clock_skew_secs < 0 || value.max_clock_skew_secs > 300) {
    throw new DpopSignError("durable DPoP authority has invalid identity or freshness bounds");
  }
  return value;
}

function signProof(params: SignDpopProofParams, authority?: DpopReplayAuthority): DpopProof {
  const {
    capabilityId,
    toolServer,
    toolName,
    actionArgs,
    agentSeedHex,
    nonce = randomBytes(16).toString("hex"),
    issuedAt = Math.floor(Date.now() / 1000),
  } = params;

  try {
    if (authority && (!Number.isSafeInteger(issuedAt) || issuedAt < 0
      || issuedAt > 9_007_199_254_740 - authority.proof_ttl_secs
      || Buffer.byteLength(nonce, "utf8") > 4096 || Buffer.byteLength(capabilityId, "utf8") > 4096)) {
      throw new DpopSignError("durable DPoP proof exceeds its identity or clock bounds");
    }
    // Compute action_hash: SHA-256 hex of canonical JSON of actionArgs
    const actionHash = sha256Hex(canonicalizeJson(actionArgs));

    // Derive agent public key from seed
    const { public_key_hex: agentKey, signature_hex: _unused } = signEd25519Message(
      "derive_key",
      agentSeedHex,
    );

    // Build body with fields in alphabetical order (matches canonical JSON and Rust serde)
    const body: DpopProofBody = {
      action_hash: actionHash,
      agent_key: agentKey,
      capability_id: capabilityId,
      issued_at: issuedAt,
      nonce,
      schema: authority ? DPOP_AUTHORITY_SCHEMA : DPOP_SCHEMA,
      tool_name: toolName,
      tool_server: toolServer,
    };
    if (authority) body.replay_authority = authority;

    // Sign canonical JSON of body
    const bodyCanonical = canonicalizeJson(body);
    const { signature_hex } = signEd25519Message(Buffer.from(bodyCanonical, "utf8"), agentSeedHex);

    return { body, signature: signature_hex };
  } catch (cause) {
    if (cause instanceof DpopSignError) {
      throw cause;
    }
    throw new DpopSignError("failed to sign DPoP proof", { cause });
  }
}
