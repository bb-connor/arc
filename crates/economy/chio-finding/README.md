# chio-finding

`chio-finding` defines signed information goods and the artifacts used to
admit, purchase, challenge, audit, retract, and recover them in Chio's
cognition market. It supplies pure validation and canonical signing helpers.
Storage, receipt resolution, clock selection, and market execution belong to
the consuming service.

## Usage

Sign an asserted finding with a commitment to its reveal envelope. These
references are illustrative; verification below checks the artifact itself.

```rust
use chio_core_types::capability::scope::MonetaryAmount;
use chio_finding::{
    compute_finding_id, crypto::Keypair, finding_payload_sha256, sign_finding,
    verify_finding,
    Finding, FindingDescriptor, FindingEvidenceClass, FindingGuaranteeClass,
    FindingOutcomeClass, FINDING_SCHEMA_V1,
};

let issuer = Keypair::from_seed(&[7; 32]);
let mut draft = Finding {
    schema: FINDING_SCHEMA_V1.into(),
    finding_id: String::new(),
    descriptor: FindingDescriptor {
        topic: "example:measurement".into(),
        context_sha256: "a".repeat(64),
        outcome_class: FindingOutcomeClass::PositiveResult,
    },
    guarantee_class: FindingGuaranteeClass::Asserted,
    payload_sha256: finding_payload_sha256("text/plain", b"result")?,
    payload_media_type: "text/plain".into(),
    evidence_receipt_ids: vec![],
    evidence_checkpoint_ref: "checkpoint/example".into(),
    evidence_cost: MonetaryAmount { units: 0, currency: "USD".into() },
    runtime_assurance_tier: None,
    evidence_class: FindingEvidenceClass::Asserted,
    replay_recipe_sha256: None,
    intent_commitment_receipt_id: None,
    bond_ref: "bond/example".into(),
    status_feed_ref: "status/example".into(),
    license_ref: None,
    price_hint_ref: None,
    issuer: issuer.public_key(),
    issued_at: 100,
    expires_at: 200,
    signature: String::new(),
};
draft.finding_id = compute_finding_id(&draft)?;
let signed = sign_finding(draft, &issuer)?;
verify_finding(&signed)?;
assert_eq!(signed.finding_id.len(), 64);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Guarantees

- `Finding::validate` checks the schema, bounded fields, safe integers,
  currency, unique receipt references, class prerequisites, validity-window
  shape, Ed25519 issuer strength, and content-addressed identity.
- `compute_finding_id` derives the identifier; `sign_finding` validates and
  binds it into the inline signature. `verify_finding` checks that signature
  with strict verification.
- `verify_pinned_envelope` requires a non-weak Ed25519 authority key and an
  identical embedded signer. Family verifiers add their body checks; seller
  authorization and market terms derive their signer from the body.
- `verify_status_proof_input` checks a sparse proof against its authenticated
  epoch, feed authorization, and supplied freshness policy.

Validate original finding JSON against the registered schema before typed
deserialization. `verify_finding` accepts a typed value and cannot recover
noncanonical key encodings or explicit nulls normalized during parsing.
Its validity check is clockless. Consumers must authenticate referenced
evidence, resolve bonds and status, and check current liveness separately.

## Status

The crate implements finding and supporting artifact contracts, including
status-proof and recovery carriers. It has no I/O, durable store, receipt
fetcher, status-feed resolver, or kernel wiring. Its Cargo package is marked
`publish = false`.

## Related

- [Architecture](ARCHITECTURE.md)
- [Finding protocol family](../../../spec/PROTOCOL.md#647-finding-artifact-family)
- [Open-market admission](../chio-open-market/README.md)
- [License](../../../LICENSE)
