# chio-governance

`chio-governance` defines signed governance charters, registry cases, capability
leases, and destructive-action receipts. Registry evaluation computes a local
case result; workflow callers use separate lease and receipt checks.

## Usage

Sign and verify a scoped lease with a deterministic fixture key. A deployment
must additionally pin the signer and bind issuer and subject to its own policy.

```rust
use chio_governance::crypto::Keypair;
use chio_governance::lease::{
    CapabilityLeaseArtifact, CapabilityLeaseActionClass, SignedCapabilityLease,
    CAPABILITY_LEASE_SCHEMA_V1, verify_capability_lease,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signer = Keypair::from_seed(&[11; 32]);
    let scope = "a".repeat(64);
    let lease = SignedCapabilityLease::sign(CapabilityLeaseArtifact {
        schema: CAPABILITY_LEASE_SCHEMA_V1.into(),
        lease_id: "lease-1".into(), issuer: "operator-1".into(),
        subject: "agent-1".into(), scope_digest: scope.clone(),
        action_class: CapabilityLeaseActionClass::ScopedObservation,
        issued_at_unix_ms: 1_000, expires_at_unix_ms: 2_000,
    }, &signer)?;
    verify_capability_lease(&lease, 1_500, Some(scope))?;
    Ok(())
}
```

## Guarantees

- `verify_capability_lease` checks schema, required fields, signature, lifetime,
  and an optional expected scope digest. Expiration is exclusive.
- `verify_destructive_authorization` adds exact lease, workflow, and step-hash
  matching to receipt signature and lifetime checks.
- `evaluate_generic_governance_case` checks signed artifacts and case bindings.
  Only enforced freeze or sanction cases set `blocks_admission` to true.
- Failed case evaluation can return `Ok` with findings and
  `blocks_admission: false`. Callers must inspect findings before admitting work.

## Status

The artifact and evaluation APIs are implemented. They perform no persistence,
revocation lookup, global arbitration, or automatic sanction propagation.
Envelope verification uses its carried signer key; external authority pinning
and applying the result to current admission state belong to the caller.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol certification and registry](../../../spec/PROTOCOL.md#12-certification-contract)
- [Listing artifacts](../../economy/chio-listing/README.md)

## License

[Workspace license](../../../LICENSE)
