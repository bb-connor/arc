# chio-pheromone-runtime

Local receiver for federated pheromone batches, with SQLite-backed admission
state and durable receive reports. It connects signed transit policy,
workflow-proof resolution, deposit validation, and concentration queries.

## Usage

Open an in-memory receiver store and import verifier-owned peer weights. This
example performs local configuration and storage operations without receiving a
network batch or deciding tool admission.

```rust
use chio_pheromone_runtime::{peer_weights_from_json, PeerWeightProvider,
    PheromoneRuntimeStore};
use chio_pheromone_runtime::store::SqlitePheromoneRuntimeStore;

let store = SqlitePheromoneRuntimeStore::open_in_memory()?;
assert!(store.receive_reports()?.is_empty());
let weights = peer_weights_from_json(r#"{
  "schema":"chio.pheromone.peer-weights.v1",
  "reputationEpoch":42,
  "weights":[{"kernelId":"did:chio:peer","weight":0.5}]
}"#)?;
assert_eq!(weights.weight("did:chio:peer", 42)?, 0.5);
assert!(weights.weight("did:chio:peer", 43).is_err());
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Guarantees

- `runtime_policy_from_json` verifies a signed policy against external issuer
  roots and validates explicit scarcity, admission, and trust-floor material.
- SQLite `receive_batch` verifies batch/frame transit and resolves workflow
  context before treaty-scoped deposit admission.
- Accepted deposits, replay/quota state, and the receive report commit in one
  transaction. A failed frame rolls back to its savepoint; mixed results report
  `Partial` with `accepted = false`.
- `VerifiedChioWorkflowResolver::from_verified_package` verifies the package
  and resolves exact workflow, receipt, intersection, and step references.

## Status

Implemented local receiver and persistent store. `open(path)` persists state;
`open_in_memory` creates an ephemeral database. The store trait's default live
receive and scoped-admission methods fail closed. Callers wire transport,
refresh trusted time and local policy, and decide whether concentration may
influence tool admission. The crate declares no Cargo features and is
unpublished (`publish = false`).

## Related

- [Architecture](ARCHITECTURE.md)
- [Trust-control contract](../../../spec/PROTOCOL.md#9-trust-control-contract)
- [Deposit substrate](../chio-pheromone/README.md)
- [Relay service](../chio-pheromone-relay/README.md)

[License](../../../LICENSE)
