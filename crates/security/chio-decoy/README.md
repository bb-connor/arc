# chio-decoy

`chio-decoy` manages private deception records, file materialization, tripwire
matching, and signed output watermarks for Chio security integrations. Records
bind a tenant, surface, version, lifecycle, and expiry to an artifact.

## Usage

Compute the first lifecycle transition without creating files or registry rows.
The hashes below are fixture values for an already constructed record.

```rust
use chio_decoy::transition;
use chio_security_types::ports::{ArtifactId, Digest32, RecordId, TenantId};
use chio_security_types::{
    DecoyLifecycle, DecoyOperationAttempt, DecoyOperationKind, DecoyRecord,
    DecoySurface, DecoyVersion,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let current = DecoyRecord {
        tenant_id: TenantId::new("tenant-a")?,
        artifact_id: ArtifactId::new("credential-a")?,
        public_marker_ref: None,
        surface: DecoySurface::CredentialFile,
        scope_id: RecordId::new("scope-a")?,
        marker_digest: Digest32::new([1; 32]),
        creation_policy_id: RecordId::new("policy-a")?,
        version: DecoyVersion::new(1)?,
        version_hash: Digest32::new([2; 32]),
        lifecycle: DecoyLifecycle::Planned,
        generation: 0,
        expires_at_unix_ms: 9_000,
        predecessor_artifact_id: None,
        successor_artifact_id: None,
    };
    let attempt = DecoyOperationAttempt {
        operation_id: RecordId::new("materialize-a")?,
        kind: DecoyOperationKind::BeginMaterialization,
        expected_generation: current.generation,
        expected_version: current.version,
        successor_artifact_id: None,
    };
    let next = transition(&current, &attempt, None)?;
    assert_eq!(next.lifecycle, DecoyLifecycle::Materializing);
    assert_eq!(next.generation, 1);
    Ok(())
}
```

## Guarantees

- `transition` validates record shape, generation, version, and legal edges.
  `ArmedReplacement` binds retirement to a distinct successor in a matchable
  lifecycle: `Armed`, `Triggered`, or `Rotating`.
- `PrivateDecoyRegistry` seals private envelopes with ChaCha20-Poly1305 and
  uses domain-separated HMAC indexes. Its store receives ciphertext and keyed
  lookup tokens; persistence and atomic compare-and-swap belong to the store.
- `DecoyDetector::detect` distinguishes active, inactive, and clear results.
  Direct presentation of an active marker requests immediate denial; a match
  always carries `malice_proven: false`.
- `FileMaterializer` uses ownership proofs and descriptor-based traversal to
  publish and remove owned files. Non-Unix materialization returns `Unsupported`.
- `WatermarkVerifier::scan_text` checks canonical encoding, signature, key
  validity, registry state, and expiry while retaining candidate advisories.

## Status

Implemented lifecycle, sealed-registry coordination, filesystem operations, and
watermark issuance/verification. Key providers, authorization, sequence stores,
observation stores, and enforcement consumers are supplied by the embedding
runtime. Filesystem operations require supported locking and extended attributes.
No Cargo features are declared.

## Related

- [Architecture](ARCHITECTURE.md)
- [Trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [Quarantine](../chio-quarantine/README.md)

[License](../../../LICENSE)
