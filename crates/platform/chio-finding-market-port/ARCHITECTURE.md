# chio-finding-market-port architecture

## Responsibility and boundary

This crate owns the shared tenant identity, principal roles, authentication
ports, domain backend port, and event grammar used by hosted market adapters.
Its public surface contains no connection pool or HTTP listener. Applications
pass an explicit `HostedTenantId` independently of resource identifiers.

`HostedAuthPort` retrieves principals and active API keys and consumes a
capability DPoP admission. `HostedApiKeyLifecyclePort` couples issue/revoke
operations with their security-event artifact. `HostedMarketBackend` exposes
readiness, append, single-finding reads, keyset pages, and non-live status
lookups. Each trait is `Send + Sync` and uses `async_trait`.

## Structure

`lib.rs` defines identity construction, the five `HostedPrincipalRole`
variants, principal/key records, authentication traits, and admission outcomes.
`grammar.rs` defines `HostedAggregateKind` and `HostedMarketDomainEventKind`.
`backend.rs` defines mutations, delivery artifacts, read projections, pages,
and the durable backend trait.

The grammar binds each event kind to exactly one aggregate label and schema.
It includes publication, recipe/profile/collateral registration, purchase and
delivery terminals, challenges, retractions, enforcement, status, and audit.
A recipe event names the unsigned replay-recipe input schema. A delivery event
names the hosted wrapper containing a kernel receipt.

## Data and control flow

The edge resolves an event using `from_event_kind`, then sends a
`HostedDomainMutation` to `HostedMarketBackend::append`. The mutation carries
an aggregate id, event id, expected revision, optional previous-event digest,
optional signer pin, and a JSON payload. The adapter returns `Inserted` or
`ExactReplay`; revision and artifact checks belong to that implementation.

`HostedHttpProjection` carries revision, previous/current event digests,
artifact schema/digest, payload, and commit time. `HostedHttpPage` adds an
optional next cursor. Non-live lookups return a `BTreeSet` of finding ids.

Authentication admission has four outcomes: `Admitted`,
`RetriedSameRequest`, `Replay`, and `BudgetExceeded`. The retry outcome permits
a resumable idempotent request; it must be distinguished from a different
request reusing the proof. `HostedCapabilityAdmission` carries the optional
request digest and the capability expiration separately from proof validity.

## Trust and invariants

`HostedTenantId::new` validates a nonempty bounded ASCII identifier. Its derived
`Deserialize` implementation directly accepts the transparent string; it does
not call `new`. External tenant selectors therefore require constructor
validation at their ingress boundary.

`HostedDomainMutation` uses camelCase and `deny_unknown_fields`.
`artifact_authority_id` is skipped by serde, allowing the authenticated edge to
resolve authority without accepting a wire assertion for that field. Other
public record fields remain caller supplied and require adapter validation.

`HostedMarketPortError` and `HostedMarketBackendError` distinguish malformed
input, corrupt durable JSON, conflicts, capacity, and unavailable dependencies.
Their JSON variants retain the shared parser cause. The traits provide no
default cryptographic or transactional implementation.

## Dependencies and verification

`chio-core-types` supplies public keys, receipts, and shared JSON errors.
Serde defines wire shapes; `async-trait` supports asynchronous ports; `thiserror`
defines the error vocabulary. There are no Cargo feature switches.

Unit tests exercise tenant length/alphabet rejection, closed role parsing,
unique event names, and aggregate-label round trips. A focused command is
`cargo test -p chio-finding-market-port --lib`. These tests run offline and
exercise contracts independently of the PostgreSQL adapter.
