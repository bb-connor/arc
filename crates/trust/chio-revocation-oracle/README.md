# chio-revocation-oracle

`chio-revocation-oracle` provides an in-memory append-only revocation log,
Ed25519-signed epoch roots, freshness checks, and a passport event bridge.
It also implements a separate sparse map for portable finding-status proofs.

## Usage

Insert a revoked key and verify its inclusion proof and signed root locally.
The deterministic key is a fixture; production receivers pin their oracle key.

```rust
use chio_core_types::Keypair;
use chio_revocation_oracle::{
    Ed25519RootSigner, EpochNonce, InMemoryRevocationOracle,
    RevocationKey, RevocationOracle, FreshnessConfig, verify_fresh_epoch_root,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signer = Ed25519RootSigner::new("oracle-1", Keypair::from_seed(&[7; 32]));
    let mut oracle = InMemoryRevocationOracle::new();
    let key = RevocationKey::new("subject-1", EpochNonce::new(4));
    let root = oracle.insert(key.clone(), 1_000)?;
    let proof = oracle.inclusion_proof(&key)?;
    InMemoryRevocationOracle::verify_inclusion(&proof)?;
    oracle.signed_epoch_root(&signer)?.verify(&signer.verifier())?;
    verify_fresh_epoch_root(&root, 1_000, FreshnessConfig::fail_closed())?;
    assert!(oracle.contains(&key));
    Ok(())
}
```

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Empty | Enables no optional functionality. |
| `delegation` | Off | Enables swarm and receipt-chain integration test targets; library APIs are unchanged. |

## Guarantees

- `insert` rejects duplicate or padded/empty subject keys, advances the epoch,
  and keeps issuance time nondecreasing when the supplied clock moves backward.
- `Ed25519RootVerifier` checks pinned signer ID, signature size, and the signing
  wrapper over the canonical root under `chio.trust.passport-revocation-root.v1`.
  The pinned key alone selects the algorithm. Freshness is a separate check.
- `verify_fresh_epoch_root` rejects future roots and excessive age. Its default
  permits zero age; configured staleness and offline grace are added together.
- General `NonInclusionProof` checks require the originating oracle state.
  Finding-status sparse proofs independently verify a 256-sibling path.

## Status

Storage is in memory. Broadcasters are caller-driven, and the included queue
can drop its oldest root when full. No scheduler or network transport runs here.
Passport bridge keys use subject and revocation timestamp; passport ID is
metadata and does not distinguish keys for equal subject/timestamp pairs.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol verification rules](../../../spec/PROTOCOL.md#53-verification-rules)
- [Credentials](../chio-credentials/README.md)

## License

[Workspace license](../../../LICENSE)
