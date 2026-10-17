# Chio DPoP Integration Guide

DPoP (Demonstration of Proof-of-Possession) is Chio's sender-constrained
invocation profile. When a `ToolGrant` carries `dpop_required: Some(true)`, the
kernel requires a fresh cryptographic proof with every invocation. The proof
binds the call to the agent's keypair, capability token, target tool, arguments
and independently configured replay authority.

## When DPoP Is Required

The `dpop_required` field on `ToolGrant` controls enforcement. `Some(true)`
requires a valid proof. `None` and `Some(false)` do not require DPoP for that
grant. A missing or invalid proof denies an invocation against a grant that
requires DPoP.

## Proof Format

The sole Chio DPoP schema is `chio.dpop_proof.v1`. The proof is a Chio-native
signed structure using RFC 8785 canonical JSON, not a JWT. Its body contains:

| Field | Meaning |
|-------|---------|
| `schema` | Exactly `chio.dpop_proof.v1` |
| `capability_id` | ID of the capability token being used |
| `tool_server` | ID of the target tool server |
| `tool_name` | Name of the tool being called |
| `action_hash` | SHA-256 hex of canonical JSON of the tool arguments |
| `nonce` | Caller-generated replay identifier |
| `issued_at` | Unix seconds when the proof was created |
| `agent_key` | Public key of the signer |
| `replay_authority` | Required destination, source generation and freshness policy |

The envelope contains `body` and `signature`. The signature covers the entire
canonical body, including `replay_authority`. Rust decoding rejects unknown
body and envelope fields. Missing or null authority is invalid.

## Replay Authority

`replay_authority` contains exactly five fields:

| Field | Validation |
|-------|------------|
| `destination_store_uuid` | Canonical lowercase, non-nil destination UUID |
| `dpop_authority_id` | Nonempty, unpadded authority name without control characters, at most 512 UTF-8 bytes |
| `expectation_id` | Destination-derived source-generation digest, 64 lowercase hexadecimal characters |
| `proof_ttl_secs` | Inclusive proof lifetime, an integer from 1 to 3,600 seconds |
| `max_clock_skew_secs` | Future-date tolerance, an integer from 0 to 300 seconds |

The signer obtains this descriptor through authenticated configuration. The
verifier independently selects its expected authority and requires an exact
match across all five fields. It must not choose the expected authority from
the proof it is checking. Altering any authority field requires a new signature.
A descriptor alone does not prove that its authority is activated.

## Verification and Admission

Proof verification checks the schema, complete authority, sender, invocation
binding, freshness, signature and resource bounds:

- `agent_key` must equal the capability's subject.
- `capability_id`, `tool_server`, `tool_name` and `action_hash` must match the
  invocation being evaluated.
- `issued_at + proof_ttl_secs >= now` and
  `issued_at <= now + max_clock_skew_secs`, using the independently selected
  authority's immutable freshness policy and trusted clock.
- Issue time plus TTL must fit the supported range `0..=9007199254740`.
- Nonce and capability ID must each fit within 4,096 UTF-8 bytes.
- The signature must verify over the complete canonical proof body.

Non-consuming cryptographic verification does not reserve a nonce or permit
execution. Admission also requires current capability and policy checks and
operation-owned replay custody through the configured authority. A valid proof
cannot choose or replace that custody. Capacity exhaustion denies new
reservations without evicting live replay markers.

DPoP alone does not authorize an external payment rail call. Payment execution
also requires the kernel's execution-nonce or governed-approval checks and the
configured durable stores for those credential paths.

## Generating Proofs (Rust)

Obtain `replay_authority` from authenticated configuration as a
`chio_kernel::dpop::authority::DpopReplayAuthority`. Include it in the body before
signing:

```rust
use chio_kernel::dpop::{DpopProof, DpopProofBody, DPOP_SCHEMA};

let body = DpopProofBody {
    schema: DPOP_SCHEMA.to_string(),
    replay_authority,
    capability_id: token.id.clone(),
    tool_server: "filesystem".to_string(),
    tool_name: "read_file".to_string(),
    action_hash: sha256_hex_of_canonical_args(&args),
    nonce: random_hex_16(),
    issued_at: unix_now_secs(),
    agent_key: agent_keypair.public_key(),
};

let proof = DpopProof::sign(body, &agent_keypair)?;
```

Attach `proof` to `ToolCallRequest.dpop_proof` before sending. The application
supplies the token, arguments, keypair, replay authority, clock and random nonce
in this example.

## Generating Proofs (TypeScript SDK)

[`signDpopProof`](SDK_TYPESCRIPT_REFERENCE.md#signdpopproof) requires a
`replayAuthority` parameter. It emits the same `chio.dpop_proof.v1` body and
signs it with Ed25519. Missing, null or invalid authority is rejected before
signing. The SDK copies the validated authority so later changes to the caller's
configuration object do not change an already signed proof.

## Generating Proofs (C++ SDK)

`chio::sign_dpop_proof(params, authority)` requires a separate
`DpopReplayAuthority`. `DpopProofBuilder` requires the authority in its
constructor. Both produce the same signed `chio.dpop_proof.v1` body; neither
provides an authority-free signing path.

### Runtime authority selection

A serving kernel accepts DPoP only with an independently configured authority that is already active in its durable store. Ordinary startup loads that activation; it does not create or replace one. `DurableAdmissionRuntime::attach` takes the optional configured descriptor and verifies it before startup reconciliation.

`CHIO_DPOP_REPLAY_AUTHORITY_FILE` is the one configuration point for the descriptor. It names a regular JSON file bounded to 4096 bytes; duplicate fields are rejected. Chio policies, HushSpec policies and the CLI API-protect runtime all read it, and no policy field carries a descriptor. When any default grant requires DPoP and the variable is unset, startup is refused with `a DPoP-required policy needs CHIO_DPOP_REPLAY_AUTHORITY_FILE`; an unreadable, oversized or invalid file is refused at startup too. The selected descriptor must match the attached store, source generation and freshness policy exactly.

Explicit deployment initialization can call `initialize_local_dpop_authority` with its serving store, chosen authority ID, freshness policy and trusted clock. Reopening uses `load_local_dpop_authority`; an absent or inactive record is an error. `finding operator init` provisions its authority once, and `finding operator serve` only loads it.
