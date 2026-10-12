# chio-custody-hw

Passkey capability issuance and mobile attestation verification for Chio.
The issuer signs audience-bound, five-minute capabilities through an injected
`SigningBackend`. Separate stores implement replay, revocation, and mobile
challenge/counter state.

## Usage

Mint with fixture assertion evidence and explicitly wired in-memory gates:

```rust
use std::sync::Arc;
use chio_core_types::crypto::{Ed25519Backend, Keypair};
use chio_custody_hw::{
    InMemoryCredentialRevocationOracle, InMemoryPasskeyNonceStore,
    IssuerService, MintRequest, ScopeSet, VerifiedAssertion,
};
let issuer = IssuerService::with_signer("kernel-a", Arc::new(
    Ed25519Backend::new(Keypair::from_seed(&[7; 32]))
))
.with_nonce_store(Arc::new(InMemoryPasskeyNonceStore::new()))
.with_revocation_oracle(Arc::new(InMemoryCredentialRevocationOracle::new()))
.enforce_revocation_replay()?;
let verified = VerifiedAssertion {
    credential_id_b64: "credential_a".into(), user_verified: true,
};
let request = MintRequest {
    audience: "kernel-a".into(), scope_set: ScopeSet::new(["tool:read"]),
    challenge_nonce: "challenge_a".into(),
};
let now = chrono::DateTime::parse_from_rfc3339("2026-04-29T12:00:00Z")?
    .with_timezone(&chrono::Utc);
let minted = issuer.mint_capability(&verified, &request, now)?;
assert!(!minted.capability.signature.is_empty());
assert!(issuer.mint_capability(&verified, &request, now).is_err());
# Ok::<(), Box<dyn std::error::Error>>(())
```

Real assertion evidence comes from `PasskeyVerifier::verify_assertion` with
server-owned authentication state. Use `with_durable_stores_handle` when
replay/revocation must survive restart and operator revocations share the cache.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Yes | Enables `passkey` and `sqlite-store`. |
| `passkey` | Yes | Adds WebAuthn relying-party verification and its dependencies. |
| `sqlite-store` | Yes | Adds durable nonce, revocation, mobile challenge, and counter stores. |
| `pq` | No | Enables core hybrid ML-DSA signing support. |
| `dev-fixtures` | No | Enables synthetic App Attest and caller-JWKS test paths; exclude from deployment builds. |

## Guarantees

- `mint_capability` checks audience, user verification, transport fields,
  configured rate/revocation/replay gates, then signs canonical unsigned bytes.
- `with_signer` wires rate limiting only. `enforce_revocation_replay` refuses
  construction unless both replay and revocation stores are attached.
- `MobileChallengeAuthority` verifies stored application-bound evidence before
  atomically consuming the challenge and advancing App Attest counter state.
- Canonical capability parsing checks original bytes; callers separately check
  signature, audience, expiry, scope, and revocation before accepting authority.

## Status

Implemented issuance and verification surfaces with synthetic test corpora.
The production Play Integrity path rejects every token while its key pin is
synthetic. App Attest callers must select the production AAGUID policy and
retain prior counters; the challenge authority fixes those choices.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol contract](../../../spec/PROTOCOL.md#9-trust-control-contract)
- [chio-revocation-oracle](../chio-revocation-oracle/README.md)

[License](../../../LICENSE)
