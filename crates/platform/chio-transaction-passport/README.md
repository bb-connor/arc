# chio-transaction-passport

Authenticates transaction passport roots and checks their committed evidence
graph, claim set, verifier policy, and selected proof families. It supplies
the common verifier primitives used by commerce, enterprise, and Agent Web
proof consumers.

## Usage

Sign and authenticate a local root with an explicit signer pin. The example
checks the root signature; committed artifact bytes are checked by the
artifact entrypoints. Consumers select trusted keys independently of
received passports.

```rust
use chio_core_types::Keypair;
use chio_transaction_passport::{sign_transaction_passport,
    verify_transaction_passport_signature, TransactionPassport,
    TRANSACTION_PASSPORT_SCHEMA_ID};

let key = Keypair::from_seed(&[7; 32]);
let mut passport = TransactionPassport {
    schema: TRANSACTION_PASSPORT_SCHEMA_ID.into(), id: "passport-demo".into(),
    issued_at: "2026-06-10T00:00:00Z".into(),
    not_before: None, expires_at: None,
    issuer: format!("did:chio:{}", key.public_key().to_hex()),
    evidence_graph_sha256: "a".repeat(64),
    evidence_graph_path: "evidence-graph.json".into(),
    claim_set_sha256: "b".repeat(64), claim_set_path: "claim-set.json".into(),
    verifier_policy_sha256: "c".repeat(64),
    verifier_policy_path: "verifier-policy.json".into(),
    omission_policy: vec![], signature: String::new(),
};
passport.signature = sign_transaction_passport(&passport, &key)?;
verify_transaction_passport_signature(&passport, &[key.public_key()])?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Guarantees

`verify_transaction_passport_signature` checks schema/validity, requires
caller-pinned root keys, and verifies the canonical body against the
self-certifying issuer. `verify_minimal_passport_schema_at` accepts a
supplied time for deterministic validity checks.

`decode_evidence_json` validates bounded original JSON before projection.
`verify_passport_root_and_claim_set_artifacts` combines root authentication
with artifact and claim checks. Transparency anchoring requires separate
checkpoint pins through `TransactionTrustAnchors`.

## Status

Implemented root/artifact, runtime-security, and cognition-market
verification APIs. `verify_minimal_passport_artifacts` checks shape and
commitments without authenticating the root signature. Explicit
unchecked-signature variants require an already authenticated caller
context. Evidence verification uses supplied artifacts and trust; it does
not operate tools or settle purchases.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol](../../../spec/PROTOCOL.md#643-transaction-passport-proof-root)
- [chio-enterprise-export](../chio-enterprise-export/README.md)
- [License](../../../LICENSE)
