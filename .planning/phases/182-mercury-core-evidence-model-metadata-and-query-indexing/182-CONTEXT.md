# Phase 182: MERCURY Core Evidence Model, Metadata, and Query Indexing - Context

**Gathered:** 2026-04-02
**Status:** Complete

<domain>
## Phase Boundary

Build the typed MERCURY evidence layer and indexed retrieval foundation on top
of ARC's existing receipt and persistence substrate.

</domain>

<decisions>
## Implementation Decisions

### New Crate, Existing Truth
- create `crates/arc-mercury-core`
- do not fork `ArcReceipt` or `KernelCheckpoint`
- serialize typed MERCURY data into `receipt.metadata.mercury`

### Indexed Querying From Day One
- primary workflow identifiers must not rely on JSON scans over `raw_json`
- extend SQLite storage with extracted MERCURY index data keyed by `receipt_id`

### Type The Product Semantics Early
- type business IDs, chronology/causality, provenance, sensitivity, disclosure,
  and approval state before building package/export wrappers

### Phase Sequencing
- start only after phase `181` freezes the workflow sentence and ARC reuse map
- this phase becomes the contract input for package/export work in phase `183`

</decisions>

<code_context>
## Existing Surfaces

- `crates/arc-core/src/receipt.rs`
- `crates/arc-store-sqlite/src/receipt_store.rs`
- `crates/arc-kernel/src/receipt_query.rs`
- `crates/arc-store-sqlite/src/receipt_query.rs`
- `docs/mercury/PHASE_0_1_BUILD_CHECKLIST.md`
- `docs/mercury/ARC_MODULE_MAPPING.md`

</code_context>

<deferred>
## Deferred Ideas

- remote APIs, UI surfaces, and partner connectors remain out of scope until
  the local proof chain and query model are stable

</deferred>
