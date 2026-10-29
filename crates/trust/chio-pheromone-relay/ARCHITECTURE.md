# chio-pheromone-relay architecture

## Responsibility and boundary

`PheromoneRelayService` owns HTTP request handling and durable delivery
coordination. `PheromoneRelayClient` signs outbound requests for configured
peers. `SqlitePheromoneRelayStore` owns relay custody, retries, replay nonces,
catchup cursors, receive reservations, and event records.

A `RelayBatchReceiver` supplies actual deposit admission. The relay trusts its
returned receive report only through the authenticated sender and request path.
The receiver's durable report lookup is an explicit crash-recovery hook.
Peer discovery, trust establishment outside the pinned directory, tool
admission, settlement, and operator delivery actions belong to callers.

## Structure

| Module | Responsibility |
|--------|----------------|
| `service`, `client` | Axum listener/router, signed outbound delivery, ticks |
| `http_signing` | Request signatures, freshness, nonce-recording boundary |
| `directory`, `validation` | Peer pins, signed bundles, rotation, profile limits |
| `store` | SQLite relay custody and operator queries |
| `metrics`, `schema`, `error`, `input` | Observation, wire labels, bounded readers |
| `alerts` | Routing, suppression, handoff, trend evaluation |
| `delivery`, `delivery_report` | Normalization, acknowledgement, drift, strict decode |
| `assurance` | Replay/recovery/retention reports and signed export bundles |
| `archive` | Package signing, extraction, restore and external-retention review |

## Data and control flow

1. Load a peer directory under the selected local-development or production
   profile, with external issuer pins for signed directory bundles.
2. Authenticate a relay request's canonical signing material, path/body digest,
   recipient, sender key, freshness window, and persisted replay nonce.
3. Check sender/treaty, relay role, frame count, and transit-ladder scope against
   the directory. Call `RelayBatchReceiver` with the authenticated sender.
4. Record the returned report in the relay inbox, then emit the receive event.
   Runtime receipt persistence and relay inbox recording are separate commits.
5. Outbound ticks lease due batches, sign fresh HTTP requests, and persist
   delivery, retry, or dead-letter outcomes. Catchup advances peer/treaty cursors.

Alert and assurance helpers evaluate supplied reports against explicit routing,
retention, signer, or archive profiles. Export/archive signatures bind manifest
members and hashes. Calling these helpers does not perform a webhook delivery,
external archival operation, or operator acknowledgement.

## Trust and invariants

Relay HTTP signatures require externally pinned directory identity. Endpoint
validation and redirect restrictions depend on `RelayProfile`; production
requires HTTPS-compatible configured peers. The crate declares no optional
Cargo features, and transport behavior is selected by profile and caller wiring.

File-backed SQLite uses WAL, FULL synchronization, and a busy timeout. The
single-writer ownership assumption matters during reopen recovery: migrations
clear only uncommitted inbox reservations. Committed reservations survive so
callers can coordinate already-admitted deposits without clearing committed
slots. The HTTP handler does not invoke reservation or durable-report recovery
methods. Transport integrations using those APIs must implement that lifecycle
and select both batch digest and authenticated sender for recovery, because
digest alone cannot distinguish sender-specific verdicts.

`RelayNonceSet` supplies process-local custody and ignores its expiry argument.
The SQLite implementation persists nonce expiry with sender/nonce uniqueness.
`open_in_memory` remains ephemeral even though it uses the same SQL operations.
Outbox enqueue persists serialized batches; callers must enter through the
service's validation boundary when relying on authenticated transport claims.

## Dependencies

`chio-federation` supplies gossip and transit types; `chio-pheromone-runtime`
supplies receive reports. `chio-core-types` supplies canonical signatures.
`axum`, `tokio`, and `chio-http-serve` supply listener and shutdown hygiene.
`chio-egress-contract` supplies the per-peer HTTP egress contract and client,
and `url` supplies endpoint parsing; `rusqlite`
supplies delivery persistence; `subtle` supplies token comparison.

## Verification

Run `cargo test -p chio-pheromone-relay` from the workspace root.
`tests/relay.rs` includes directory, service, delivery, observability, alert, and
archive suites. `tests/reader_boundaries.rs` exercises duplicate/size handling
for imported delivery, directory, and related report inputs.
The README checks sender-scoped nonce replay in an in-memory database.
Service tests use controlled peers and supplied operational evidence; deployment
must provide its own receiver, directory pins, clock, and store ownership.
