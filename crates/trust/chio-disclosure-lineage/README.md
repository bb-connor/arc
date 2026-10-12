# chio-disclosure-lineage

`chio-disclosure-lineage` verifies disclosure capsules against supplied lineage,
privacy profiles, leakage ledgers, and signed crypto-context reports. It exports
artifact types and a verifier report consumed by selective-disclosure workflows.

## Usage

Sign a local crypto-context report and verify its signature with a pinned key.
This helper authenticates report bytes; bundle verification adds policy and
reference checks. The report producer is responsible for its proof verdict.

```rust
use chio_core_types::Keypair;
use chio_disclosure_lineage::{
    DisclosureCryptoContextReport, DisclosureContextVerdict,
    DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1, sign_crypto_context_report,
    verify_crypto_context_report_signature_with_trust,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signer = Keypair::from_seed(&[7; 32]);
    let mut report = DisclosureCryptoContextReport {
        schema: DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1.into(),
        id: "report-1".into(), context_id: "context-1".into(),
        artifact_ref: "artifact-1".into(), projection_manifest_ref: "projection-1".into(),
        verdict: DisclosureContextVerdict::Rejected,
        evidence_class: "verifier_context".into(), cryptographic_proof_verified: false,
        verified_claims: vec![], rejected_checks: vec![], disclosed_fields: vec![],
        signature: None,
    };
    report.signature = Some(sign_crypto_context_report(&report, &signer)?);
    verify_crypto_context_report_signature_with_trust(&report, &[signer.public_key()])?;
    Ok(())
}
```

## Guarantees

- `verify_disclosure_lineage_bundle_with_trust` checks schemas, graph structure,
  reference bindings, reveal allowlists, leakage counts, and ledger coverage.
- Lineage and crypto-context signatures require explicitly trusted signer keys.
  Convenience verification with empty trust rejects signed artifacts.
- Graph closure checks declared parents and increasing depths. Node and edge
  digest checks hash supplied identifiers and statement strings.
- The verifier requires a signed verified crypto-context report. It does not
  execute BBS verification, prove an amount bound, or fetch source receipts.

## Status

Bundle and signature checks are implemented without storage or networking.
Privacy coverage is limited to the supplied reveal set and ledger. Callers must
establish report producer authority, source completeness, signer freshness, and
any real checkpoint inclusion or hidden-predicate proof.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol disclosure family](../../../spec/PROTOCOL.md#645-disclosure-and-lineage-family)
- [Selective disclosure](../chio-selective-disclosure/README.md)

## License

[Workspace license](../../../LICENSE)
