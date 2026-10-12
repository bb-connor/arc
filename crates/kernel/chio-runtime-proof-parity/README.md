# chio-runtime-proof-parity

Schemas and validators for Chio runtime proof parity and regeneration evidence.
The crate checks report consistency and the supplied artifact bundle so callers
can bind runtime evidence to the expected proof and workflow records.

## Usage

Validate a parity report before accepting its declaration. The hashes below
are synthetic fixtures; validation checks their format and required equality.
This example runs on a native host with the crate's existing dependencies.

```rust
use chio_runtime_proof_parity::{
    validate_runtime_proof_parity_report, RuntimeProofParityReport,
    CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA,
};

let report = RuntimeProofParityReport {
    schema: CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA.to_string(),
    run_id: "example".to_string(),
    accepted: true,
    failure_code: None,
    generated_at_unix_ms: 0,
    static_proof_package_sha256: "a".repeat(64),
    runtime_proof_package_sha256: "a".repeat(64),
    static_verifier_report_sha256: "b".repeat(64),
    runtime_verifier_report_sha256: "b".repeat(64),
    compared_fields: vec!["claim".to_string()],
    mismatches: vec![],
};
assert!(validate_runtime_proof_parity_report(&report).is_ok());
```

Use `validate_runtime_proof_regeneration_artifacts` to bind seven supplied byte
slices, including reports, manifest, proof package, and workflow receipt.

## Guarantees

- `RuntimeProofParityReport` and `RuntimeProofParityMismatch` reject unknown
  fields during typed Serde decoding.
- `validate_runtime_proof_parity_report` enforces schema and lowercase SHA-256
  syntax, acceptance/failure-code consistency, and nonempty compared fields.
  Accepted reports require equal package/report hashes and no mismatches.
- `validate_runtime_proof_regeneration_artifacts` checks run IDs, accepted
  evidence, canonical JSON hashes, source-record bindings, and manifest byte
  hashes and lengths for required roles.

## Status

Implemented evidence validation. The report validator trusts supplied hashes;
the bundle validator recomputes selected hashes from supplied artifacts.
Neither function runs a proof verifier, authenticates a workflow signer, or
establishes host enforcement. Callers obtain and authenticate evidence and
interpret the proof model's scope before granting authority.

## Related

- [Architecture](ARCHITECTURE.md)
- [Receipt contract](../../../spec/PROTOCOL.md#6-receipt-contract)
- [Portable kernel](../chio-kernel-core/README.md)
- [License](../../../LICENSE)
