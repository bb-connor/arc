# chio-finding-market-store-postgres architecture

## Responsibility and boundary

`PostgresFindingMarketStore` owns durable tenant-scoped jobs, authentication
records, aggregate journals, domain projections, and spend reservations.
It implements `HostedAuthPort`, `HostedApiKeyLifecyclePort`, and
`HostedMarketBackend`. Separate `PostgresFindingMarketMigrator`,
`PostgresFindingMarketReplicator`, and `PostgresFindingMarketRetention` types
expose schema, replication, and retention operations with their own roles.

The adapter records signed artifacts and mutable control-loop state. Calling
`reserve_monthly_spend` reserves accounting units; storing a settlement packet
records the supplied terminal. Applications supply authorization policy and
execute payment rails outside this crate.

## Structure

`lib.rs` owns DSN configuration, schema-ledger checks, migration bridging, job
creation/readback, and transaction setup. `job_leases.rs` invokes fenced SQL job
transitions. `tenant.rs` manages enabled state and configured limits.

`auth.rs` persists principals, API keys, DPoP admissions, and lifecycle evidence.
`ports.rs` maps these operations into the neutral authentication traits.
`http.rs` implements the domain backend and translates projections/errors.

`aggregates.rs` reads and verifies revision chains; `domain.rs` validates typed
artifacts and appends projections. `catalog.rs` supplies catalog operations and
`HostedDomainWrite`. `transactions.rs` groups related market writes.
`spend.rs` reserves, commits, and releases monthly units.

`checkpoints.rs` records signed aggregate checkpoints. `replication.rs` owns
authority state, replicated events, checks, and transitions. `import.rs` handles
signed SQLite import batches. `retention.rs` records checkpoint, archive, hold,
restore, quota, and garbage-collection evidence. `runtime_boundary.rs` verifies
roles, table privileges, RLS, and guarded functions; `validation.rs` handles
bounded canonical JSON, identifiers, digests, and numeric conversion.

## Connection and transaction flow

`HostedPostgresConfig` parses connection options and bounds pool size, acquire
timeout, and job capacity. It redacts its DSN in Debug and zeroizes it on drop.
Connection options force TLS with full certificate/hostname verification.
`connect` and `connect_worker` validate their role before accepting the complete
embedded SQLx version/checksum/success ledger.

Migration uses a one-connection pool and a session advisory lock. It validates
and bridges the legacy migration ledger before running `MIGRATOR`. Runtime
connections require an already current schema. Database, schema, table, and
function grants are validated independently of credentials parsing.

Tenant transactions set `chio.tenant_id` locally. Normal writes check and hold
the enabled tenant with `FOR SHARE`. Snapshot reads use repeatable-read
transactions. Worker transitions use a preliminary enabled-tenant read, then
the security-definer function locks and rechecks that tenant during the effect.

## Journal and domain invariants

Aggregate append serializes event identity and aggregate identity. An exact
replay matches retained revision, previous digest, payload bytes/digest, event
digest, and commit time. A differing replay or stale head conflicts. Event
hashes bind tenant, aggregate, revision, identity, payload digest, and time.
Immutable-event triggers prevent ordinary update/delete operations.

Domain writes additionally validate the event/schema grammar and typed artifact.
`from_canonical_payload` consumes a caller-supplied signer pin. The convenience
`from_artifact` derives the signer from the typed artifact and refuses delivery
and penalty variants that require extra pins; callers must establish authority
before using that convenience path. Delivery verifies a pinned kernel receipt;
penalty validation also binds the externally supplied authority identity.

SQL domain append requires enabled PostgreSQL mutation authority and a fresh,
matching replication check. For atomic multi-event writes, outbox rows created
inside the current transaction extend that same admission. Projection foreign
keys bind each current row to its retained event and allowed schema tuple.

`recover_purchase_result` appends reveal and terminal and finishes spend in one
transaction. Captured results commit spend; released results release it. Spend
accounting counts reserved and committed units within UTC calendar months;
shared triggers maintain the total and reject underflow or excess units.

## Job execution and retention boundaries

Claims are bounded to 100 and enforce the tenant's active-lease ceiling across
replicas. SQL uses the database clock and increments the lease fence on claim.
Renewal, fresh completion, failure, and exhaustion check owner, fence, and lease
validity. An already completed job returns `ExactReplay` for identical retained
result bytes before checking lease ownership, fence equality, or expiry;
different results conflict.
Relinquishment checks the retained leased owner and fence and refunds its attempt.
Completion accepts canonical result bytes; worker protocol/signature validation
is performed by the worker before calling it.

Retention has separately validated privileges and signed evidence types. Job
insertion shares the garbage collector's identity lock and checks tombstones,
preventing reuse of collected job identities. Archives carry object digests and
restore evidence; actual archive object transport belongs to its caller.

## Dependencies and verification

SQLx supplies TLS PostgreSQL pools, transactions, and migration execution.
`chio-finding` verifies typed finding artifacts; `chio-open-market` supplies
penalties; `chio-core-types` supplies canonicalization, hashes, and envelopes.
The neutral port crate keeps the HTTP edge independent of this SQL adapter.

`cargo test -p chio-finding-market-store-postgres --lib` exercises DSN redaction,
TLS mode, limits, canonical input, and artifact validation without a database.
The `postgres-integration` feature enables the sequenced `postgres_store` test,
which resets a dedicated database's public schema and exercises tenant isolation,
role drift, duplicate writes, authority transitions, leases, accounting,
retention, and atomic recovery. It needs six `CHIO_TEST_POSTGRES_*URL` credentials.
The ignored `worker_lease_api` test uses separately migrated TLS runtime/worker
fixtures and explicitly exercises public role and fence checks.
