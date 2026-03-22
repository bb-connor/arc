---
phase: 08-core-enforcement
plan: 02
subsystem: database
tags: [merkle, sqlite, cryptography, receipts, checkpointing, ed25519]

# Dependency graph
requires:
  - phase: 07-schema-compatibility-and-monetary-foundation
    provides: MonetaryAmount, forward-compat schema, pact-core types (MerkleTree, Keypair, canonical_json_bytes)
provides:
  - KernelCheckpoint struct with "pact.checkpoint_statement.v1" schema
  - build_checkpoint: batch signing of receipt canonical bytes via MerkleTree
  - build_inclusion_proof: per-leaf Merkle proof generation
  - verify_checkpoint_signature: Ed25519 verification of checkpoint body
  - ReceiptInclusionProof: proof struct with verify method
  - kernel_checkpoints SQLite table in SqliteReceiptStore
  - append_pact_receipt_returning_seq: returns AUTOINCREMENT seq for batch trigger
  - store_checkpoint / load_checkpoint_by_seq: checkpoint persistence and retrieval
  - receipts_canonical_bytes_range: RFC 8785 canonical bytes for Merkle leaf hashing
affects:
  - pact-kernel enforcement pipeline (batch checkpoint triggering)
  - audit / compliance layer (SEC-01, SEC-02)
  - receipt log integrity proofs

# Tech tracking
tech-stack:
  added: []
  patterns:
    - MerkleTree::from_leaves for RFC 6962 batch hashing
    - canonical_json_bytes for deterministic signing (signed body only, not full checkpoint)
    - KernelCheckpointBody + signature split (body signed, checkpoint carries both)
    - SQLite UNIQUE constraint on checkpoint_seq for idempotency

key-files:
  created:
    - crates/pact-kernel/src/checkpoint.rs
  modified:
    - crates/pact-kernel/src/lib.rs
    - crates/pact-kernel/src/receipt_store.rs
    - crates/pact-kernel/src/budget_store.rs

key-decisions:
  - "KernelCheckpointBody is the signed unit (not the full KernelCheckpoint); signature covers canonical JSON of body only"
  - "kernel_checkpoints stores signature as hex string (to_hex/from_hex) not raw bytes, matching existing crypto serialization convention"
  - "receipts_canonical_bytes_range uses canonical_json_bytes on deserialized PactReceipt for RFC 8785 determinism, not raw stored JSON"
  - "ReceiptStoreError extended with CryptoDecode and Canonical variants to avoid serde_json::Error::custom pattern"

patterns-established:
  - "Pattern: Checkpoint signing: serialize body to canonical JSON, sign bytes, store body+signature together"
  - "Pattern: Inclusion proofs: build MerkleTree from canonical bytes, call inclusion_proof(leaf_index), wrap in ReceiptInclusionProof"

requirements-completed: [SEC-01, SEC-02]

# Metrics
duration: 8min
completed: 2026-03-22
---

# Phase 8 Plan 02: Merkle Checkpoint and Receipt Store Persistence Summary

**Signed KernelCheckpoint with RFC 6962 Merkle batch root, Ed25519 body signature, SQLite kernel_checkpoints table, and inclusion proof verification for tamper-evident receipt log integrity**

## Performance

- **Duration:** 8 min
- **Started:** 2026-03-22T15:13:19Z
- **Completed:** 2026-03-22T15:20:52Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments
- KernelCheckpoint struct with "pact.checkpoint_statement.v1" schema, signed via canonical JSON of body
- build_checkpoint/build_inclusion_proof/verify_checkpoint_signature fully implemented and tested with 100-leaf batches
- kernel_checkpoints SQLite table added to SqliteReceiptStore with batch_end_seq index for checkpoint triggering queries
- append_pact_receipt_returning_seq, store_checkpoint, load_checkpoint_by_seq, receipts_canonical_bytes_range methods added

## Task Commits

Each task was committed atomically:

1. **Task 1: KernelCheckpoint, batch signing, inclusion proof types** - `f7e910b` (feat)
2. **Task 2: kernel_checkpoints table and checkpoint persistence** - `6c18354` (feat)

## Files Created/Modified
- `crates/pact-kernel/src/checkpoint.rs` - KernelCheckpointBody, KernelCheckpoint, ReceiptInclusionProof, build_checkpoint, build_inclusion_proof, verify_checkpoint_signature, 10 unit tests
- `crates/pact-kernel/src/lib.rs` - Added pub mod checkpoint, re-exports for checkpoint types
- `crates/pact-kernel/src/receipt_store.rs` - kernel_checkpoints table, 5 new methods, 6 new tests, CryptoDecode/Canonical error variants
- `crates/pact-kernel/src/budget_store.rs` - Pre-existing bug fix: added ensure_total_cost_charged_column, fixed missing field in test struct literal

## Decisions Made
- KernelCheckpointBody is the signed unit (canonical JSON of body is signed, not the full checkpoint). This matches the existing receipt signing pattern in pact-core.
- kernel_checkpoints stores signature as hex string using to_hex/from_hex, matching existing crypto serialization convention across pact-core.
- receipts_canonical_bytes_range deserializes raw_json to PactReceipt then calls canonical_json_bytes, rather than storing raw_json directly as leaf bytes. This ensures RFC 8785 determinism regardless of how the receipt was originally serialized.
- ReceiptStoreError extended with CryptoDecode and Canonical variants rather than using serde_json::Error::custom (which doesn't exist on serde_json::Error in this context).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed pre-existing budget_store.rs compilation errors**
- **Found during:** Task 1 (first attempt to compile pact-kernel tests)
- **Issue:** budget_store.rs called ensure_total_cost_charged_column (not defined), SqliteBudgetStore impl was missing try_charge_cost, list_usages lacked total_cost_charged in SELECT, test BudgetUsageRecord literals missing total_cost_charged field
- **Fix:** Added ensure_total_cost_charged_column function, added try_charge_cost for SqliteBudgetStore, fixed list_usages SELECT query, added total_cost_charged to test struct literal
- **Files modified:** crates/pact-kernel/src/budget_store.rs
- **Verification:** cargo clippy -p pact-kernel -- -D warnings passes
- **Committed in:** f7e910b (Task 1 commit)

**2. [Rule 1 - Bug] Fixed serde_json::Error::custom usage in receipt_store.rs**
- **Found during:** Task 2 (first compilation attempt of receipt_store additions)
- **Issue:** Used serde_json::Error::custom to wrap non-JSON errors, but this method doesn't exist on serde_json::Error without importing serde::de::Error trait
- **Fix:** Added CryptoDecode(String) and Canonical(String) variants to ReceiptStoreError, used those instead
- **Files modified:** crates/pact-kernel/src/receipt_store.rs
- **Verification:** Compiles clean, all tests pass
- **Committed in:** 6c18354 (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (1 blocking pre-existing, 1 bug in new code)
**Impact on plan:** Both fixes required for correctness and compilation. No scope creep.

## Issues Encountered
- budget_store.rs was in a partially-implemented state from phase 07 monetary types work (try_charge_cost added to trait but not to SqliteBudgetStore impl, total_cost_charged column logic incomplete). Fixed under Rule 3 as a blocking issue.

## Self-Check: PASSED

All artifact files verified present: checkpoint.rs, receipt_store.rs, 08-02-SUMMARY.md.
All task commits verified in git log: f7e910b, 6c18354.

## Next Phase Readiness
- checkpoint.rs and receipt_store.rs provide the Merkle batch checkpoint infrastructure needed for enforcement pipeline integration
- Consumers can trigger checkpoints by calling receipts_canonical_bytes_range after detecting batch_end_seq thresholds
- SEC-01 and SEC-02 requirements satisfied: tamper-evident receipt log integrity proofs are verifiable offline

---
*Phase: 08-core-enforcement*
*Completed: 2026-03-22*
