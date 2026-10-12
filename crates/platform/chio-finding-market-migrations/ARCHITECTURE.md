# chio-finding-market-migrations architecture

## Responsibility and boundary

This crate owns `MIGRATOR`, a compile-time SQLx migration collection. The source
SQL lives in `chio-finding-market-store-postgres/migrations`. Consumers use the
same embedded versions and checksums for schema application and runtime schema
validation. The public surface consists of a single static migrator.

Role selection, TLS connection options, legacy-ledger conversion, and the
application's migration advisory lock are implemented by the PostgreSQL adapter.
A caller invoking SQLx directly must arrange its own connection and privileges.
Inspecting `MIGRATOR.iter()` performs no database operation.

## Structure and dependencies

`src/lib.rs` invokes `sqlx_macros::migrate!` with the sibling SQL directory.
There are 24 numbered files. SQLx builds migration descriptions, checksums, SQL,
and ordering into the binary at compilation.

The dependency named `sqlx` is the `sqlx-core` package with `migrate` enabled.
`sqlx-macros` embeds the files, and `sqlx-postgres` supplies PostgreSQL migration
support. All three disable default features. This arrangement avoids pulling
SQLx's optional SQLite driver into the workspace's rusqlite library graph.
The crate declares no Cargo features and forbids unsafe Rust code.

## Schema and control flow

The ledger creates tenants and jobs, expands terminal job states, adds lease
fences, and creates principals, API-key verifiers, DPoP nonces, and capability
usage records. Tenant limits add concurrency, queue, and monthly spend bounds.
Tenant-owned tables use transaction-local `chio.tenant_id` in RLS policies.

Aggregate tables retain revision chains and current heads. Guarded append
functions serialize event identity and aggregate mutations using advisory
locks. Domain projections reference both their retained aggregate event and
an allowed aggregate/event/schema tuple. Worker transition functions use the
database clock, owner, lease fence, and enabled tenant state.

Replication migrations add authority state, signed-event storage, checks,
transitions, and outboxes. The atomic domain-batch function allows multiple
writes in one transaction to share a fresh replication admission by counting
only outbox rows created by that transaction.

Accounting migrations add nonce and spend accumulators. Shared triggers maintain
those accumulators for all writers; request bindings receive a separate live
counter because their lifetime can exceed a proof's lifetime. Rust admission
code consumes these counters when enforcing tenant capacity.

## Trust and upgrade invariants

Migration 0016 checks retained delivery rows and refuses unauthenticated legacy
delivery state with a manual-quarantine error. It replaces the earlier delivery
contract with `chio.finding.hosted-authenticated-delivery.v1`. SQL stores this
schema requirement; the adapter validates the enclosed receipt cryptographically.

Migration 0021 makes the job resurrection check take the same identity-scoped
lock used by retention collection. Migration 0022 rejects spend accumulator
underflow and changes to reservation identity or units. Migration 0024 backfills
and maintains request-binding counts.

Schema constraints and triggers depend on the database roles and grants under
which they run. SQL alone does not establish seller authorization or execute
payment rails. Runtime adapter checks and domain artifact verification complete
those boundaries.

## Verification

The README example enumerates the embedded ledger offline. This crate has no
dedicated tests. `cargo test -p chio-finding-market-migrations --doc` can check
its Rust documentation when the example is included in the doctest surface.

The adapter's feature-gated `postgres_store` test applies the ledger, bridges
legacy schema state, rejects drift and unsafe delivery upgrades, and exercises
RLS and job transitions. It requires a dedicated PostgreSQL database and
separate fixture credentials; the test resets the public schema.
