# chio-mercury-core

`chio-mercury-core` defines workflow metadata, bundle manifests, proof packages,
and review contracts for Mercury. It layers business identifiers and disclosure
projections on Chio receipts; `chio-mercury` supplies file loading and exports.

## Usage

This example validates the public fixture, embeds it under the receipt metadata
key, and derives an index record. It performs no signing or persistent writes.

```rust
use chio_mercury_core::{
    sample_mercury_receipt_metadata, MercuryContractError,
    MercuryReceiptIndexRecord, MercuryReceiptMetadata,
};

fn main() -> Result<(), MercuryContractError> {
    let metadata = sample_mercury_receipt_metadata();
    let value = metadata.into_receipt_metadata_value()?;
    let restored = MercuryReceiptMetadata::from_metadata_value(Some(&value))?;
    assert_eq!(restored, Some(metadata.clone()));

    let record = MercuryReceiptIndexRecord::from_metadata("receipt-1", &metadata);
    assert_eq!(record.workflow_id.as_deref(), Some("workflow-release-control"));
    assert_eq!(record.decision_type, "release");
    Ok(())
}
```

## Guarantees

`MercuryReceiptMetadata::validate` checks the schema, workflow identifiers,
chronology, provenance, disclosure, and each supplied bundle reference.
Optional business identifiers must be nonempty and unpadded when present.
`from_receipt` extracts and validates metadata; signature verification is a
separate operation.

`MercuryBundleManifest::canonical_bytes` validates the manifest before RFC 8785
serialization. `manifest_sha256` hashes those bytes. Artifact digest strings
are required fields; this contract has no artifact-file reader.

`MercuryProofPackage::build` emits `chio.mercury.proof_package.v1`.
`validate` also accepts legacy v1 identities and checks receipt summaries,
workflow and action bindings, manifests, derived coverage, and package identity.
Tool receipts must be mediated allow decisions with mediated trust targeting
`mercury`; observation receipts fail this acceptance check.

`verify_integrity_only` checks bundled self-signatures and inclusion evidence
and reports `scope: integrity_only`; it evaluates no signer authority. Use
`verify_with_trusted_kernel_keys` to require trusted receipt and checkpoint
signers, exact selected receipt proof coverage or bundled checkpoint-prefix
coverage, and signed manifest references; it reports
`scope: trusted_kernel_authority`. Both methods return
`verifier_equivalent: false`: portable exports do not authenticate the source
query or current source-log boundary.

## Status

Implemented typed contracts and in-memory verification. The crate owns no
receipt database, file export, or live tool mediation. `MercuryReceiptQuery`
is a filter shape; `MercuryReceiptIndexRecord` copies fields without validating
the input. Pilot and supervised-live builders supply test and CLI fixtures.
Review and distribution packages validate declared scope and artifact references;
their names do not certify an operational release or partner integration.

There are no package-defined Cargo features. Unit tests cover contract rejection,
identity tampering, receipt authority, checkpoint coverage, and inquiry projection;
`tests/integration_smoke.rs` checks public fixture shapes.

## Related

- [Architecture](ARCHITECTURE.md)
- [Receipt contract](../../../spec/PROTOCOL.md#6-receipt-contract)
- [Mercury CLI](../chio-mercury/README.md)
- [Core types](../../core/chio-core-types/README.md)
- [License](../../../LICENSE)
