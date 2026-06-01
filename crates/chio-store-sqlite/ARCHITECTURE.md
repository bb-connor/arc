# chio-store-sqlite Architecture Notes

## Module Boundaries

`receipt_store` owns receipt persistence, query support, report generation,
checkpoint projection, and evidence-retention helpers. `budget_store.rs` owns
durable grant usage, authorization holds, mutation events, replication sequence
allocation, and idempotent replay handling. The smaller store modules own
approval state, batch approval state, revocations, execution nonces,
encrypted blobs, IOU envelopes, dead letters, memory provenance, and evidence
export.

## Pain Points

`budget_store.rs` is a high-authority persistence boundary. Several SQLite row
decoders read persisted integer fields with `.max(0)` and then cast them into
unsigned Rust counters. That masks corrupt or manually edited negative
`invocation_count`, cost, sequence, hold, or mutation fields as zero. A bad row
can therefore continue through budget decisions, replication snapshots, and
idempotent retry checks as if it were a valid empty budget state.

## Security and API Constraints

Budget state must fail closed. Negative persisted values for unsigned budget
fields are storage corruption, not recoverable business data. Existing public
types and traits should remain source-compatible. Valid rows must keep the same
query and mutation behavior, mutation event ids must remain idempotent, and
replication sequence ordering must stay stable.

## Affected Dependents

No transitive crate edits are expected. Callers still use `SqliteBudgetStore`
through the existing concrete methods and `BudgetStore` trait. The behavioral
change is limited to corrupt negative SQLite rows, which now surface as
`BudgetStoreError` instead of being normalized into unsigned values.

## Planned Material Improvement

Introduce budget-store row decoding helpers that reject negative integers for
unsigned budget fields. Use them in the central usage, hold, mutation-event,
and hot-path budget state decoders so corrupted durable counters fail closed
before they can influence authorization or replication.
