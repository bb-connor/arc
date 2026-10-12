# chio-pheromone-relay

HTTP relay service and durable delivery state for federated pheromone batches.
It provides peer-directory trust, signed relay requests, inbox deduplication,
outbox retry/catchup, operator reports, alerts, and assurance export artifacts.

## Usage

Exercise SQLite relay nonce custody locally. No HTTP listener or peer connection
is started, and the in-memory database is discarded when the store is dropped.

```rust
use chio_pheromone_relay::{
    RelayNonceRecorder, SqlitePheromoneRelayStore,
};

let store = SqlitePheromoneRelayStore::open_in_memory()?;
store.record_relay_nonce("did:chio:sender", "request-1", 10_000)?;
assert!(store
    .record_relay_nonce("did:chio:sender", "request-1", 10_000)
    .is_err());
store.record_relay_nonce("did:chio:other", "request-1", 10_000)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Guarantees

- `SqlitePheromoneRelayStore` persists outbox, inbox, replay nonces, cursor,
  attempt, event, and in-flight receive reservation state.
- Relay service handlers authenticate signed HTTP requests, directory scope,
  freshness, and replay identity before handing batches to `RelayBatchReceiver`.
- Store reservation methods support single-winner receive coordination, and
  `RelayBatchReceiver` exposes sender-scoped durable-report recovery. The HTTP
  handler directly calls the receiver and records its report afterward.
- `RelayProfile::Production` applies production endpoint and directory limits.
  `LocalDev` permits local development endpoint configurations.

## Status

Implemented HTTP service/client and SQLite store with alert, delivery,
retention, and archive evidence utilities. The HTTP handler has separate runtime-receive and inbox-record commits.
Deployment supplies a trusted peer
directory, local signer, receiver, clock, and single-writer store ownership.
Assurance reports evaluate supplied operational evidence; report generation
alone does not send alerts or demonstrate external retention. The crate has
no Cargo feature switches; profile behavior is selected through configuration.
It is unpublished (`publish = false`).

## Related

- [Architecture](ARCHITECTURE.md)
- [Trust-control contract](../../../spec/PROTOCOL.md#9-trust-control-contract)
- [Receiver runtime](../chio-pheromone-runtime/README.md)
- [Federation types](../chio-federation/README.md)

[License](../../../LICENSE)
