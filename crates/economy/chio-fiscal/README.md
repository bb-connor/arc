# chio-fiscal

`chio-fiscal` defines governed fiscal charters, parameter schedules, and their
admission, approval, activation, and continuity contracts. Consumers resolve
verified schedules for tier limits, discounts, decision and insurance premiums,
and open-market fees and bonds.

## Usage

Sign and verify a one-signer charter locally. The fixed seed is an example key.

```rust
use chio_core_types::crypto::Keypair;
use chio_fiscal::{FiscalCharterBuilder, FiscalDomain, VerifiedFiscalCharter};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signer = Keypair::from_seed(&[7; 32]);
    let signed = FiscalCharterBuilder {
        governing_operator_id: "operator.example".into(),
        governed_domains: vec![FiscalDomain::TierLimits],
        signer_keys: vec![signer.public_key()],
        approval_threshold: 1,
        timelock_seconds: 10,
        proposal_ttl_seconds: 30,
        approval_ttl_seconds: 20,
        issued_at: 10,
        expires_at: 100,
        issued_by: "operator.example".into(),
        sequence: 1,
        predecessor_charter_digest: None,
    }.sign(&signer)?;
    let charter = VerifiedFiscalCharter::verify(signed)?;
    let decoded = VerifiedFiscalCharter::from_canonical_bytes(&charter.canonical_bytes()?)?;
    assert_eq!(decoded.digest(), charter.digest());
    Ok(())
}
```

Charter verification checks structure and the embedded signature. Pinning its
issuer and activating schedules require the genesis and lifecycle APIs.

## Guarantees

- `FiscalCharterBuilder::build_body` sorts and deduplicates domains, sorts
  signer IDs, rejects duplicate signers, derives the ID, and validates the body.
- `VerifiedFiscalCharter::from_canonical_bytes` and the schedule equivalent
  enforce canonical input and a 1 MiB envelope bound before verification.
- `VerifiedFiscalActivation::verify` checks admitted proposal bindings,
  current-charter signer approvals, threshold, timelock, expiry, and target.
- `commit_fiscal_continuity_advance` reverifies the advance, invokes the
  anchor's compare-and-swap, and checks the exact acknowledged checkpoint.
- `FiscalResolver::resolve` denies unavailable or divergent continuity and
  clock rollback. Fallback requires anchored state for a never-activated domain.

## Status

The crate implements verified fiscal artifacts and resolution logic. Durable
state, external anchor storage, startup recovery, and consumer wiring live in
SQLite and control-plane integrations. Signing a charter or verifying an
activation does not commit an authoritative state transition.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust-control contract](../../../spec/PROTOCOL.md#9-trust-control-contract)
- [Credit](../chio-credit/README.md)
- [Control plane](../../platform/chio-control-plane/README.md)

License: [Apache-2.0](../../../LICENSE).
