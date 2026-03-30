---
phase: 09-compliance-and-dpop
plan: "01"
subsystem: arc-kernel
tags: [compliance, retention, archival, sqlite, merkle]
dependency_graph:
  requires: [08-04]
  provides: [COMP-03, COMP-04]
  affects: [arc-kernel, arc-cli, arc-mcp-adapter, arc-guards, tests/e2e]
tech_stack:
  added:
    - RetentionConfig struct with 90-day and 10GB defaults
    - archive_receipts_before using SQLite ATTACH DATABASE
    - rotate_if_needed with time and size threshold checks
  patterns:
    - WAL mode ATTACH/DETACH for zero-copy cross-file archival
    - PRAGMA page_count * page_size for in-process size measurement
    - Median timestamp cutoff for size-triggered rotation (archives ~50% of receipts)
    - Partial-batch exclusion: only archive checkpoint rows with batch_end_seq <= max_archived_seq
key_files:
  created:
    - crates/arc-kernel/tests/retention.rs
  modified:
    - crates/arc-kernel/src/receipt_store.rs
    - crates/arc-kernel/src/lib.rs
    - crates/arc-cli/src/main.rs
    - crates/arc-mcp-adapter/src/edge.rs
    - crates/arc-guards/tests/integration.rs
    - tests/e2e/tests/full_flow.rs
    - crates/arc-bindings-core/tests/vector_fixtures.rs
    - crates/arc-bindings-core/src/capability.rs
    - crates/arc-policy/src/compiler.rs
    - crates/arc-core/tests/monetary_types.rs
    - crates/arc-core/tests/forward_compat.rs
decisions:
  - "SQLite ATTACH DATABASE used for archive writes -- avoids filesystem copy, preserves WAL atomicity"
  - "Partial batch exclusion: never archive a checkpoint whose batch_end_seq exceeds max archived seq (avoids broken inclusion proofs)"
  - "Median timestamp cutoff for size-triggered rotation -- archives approximately half the receipts each invocation"
  - "retention_config: None is the default (retention disabled) to preserve existing kernel behavior"
  - "PRAGMA page_count * page_size for DB size -- consistent with WAL mode, no filesystem stat"
metrics:
  duration: "1114 seconds"
  completed: "2026-03-22"
  tasks_completed: 1
  tasks_total: 1
  files_modified: 12
---

# Phase 09 Plan 01: Receipt Retention and Archival Summary

Receipt retention with time-based and size-based rotation: archives aged receipts to a separate SQLite file using ATTACH DATABASE, preserving Merkle checkpoint rows so archived receipts remain verifiable.

## Tasks Completed

### Task 1: Add RetentionConfig and receipt rotation methods to SqliteReceiptStore

**Status:** Complete (TDD -- RED then GREEN)

**What was built:**

- `RetentionConfig` struct with `retention_days: u64` (default 90), `max_size_bytes: u64` (default 10 GB), `archive_path: String`
- `db_size_bytes()` using `PRAGMA page_count` and `PRAGMA page_size` (WAL-safe)
- `oldest_receipt_timestamp()` using `SELECT MIN(timestamp) FROM arc_tool_receipts`
- `archive_receipts_before(cutoff, archive_path)`: ATTACHes archive DB, creates tables, copies receipts and checkpoint rows (partial-batch exclusion), deletes archived receipts, DETACHes, WAL checkpoint
- `rotate_if_needed(config)`: checks time cutoff (now - retention_days * 86400), then size threshold; uses median timestamp for size-triggered archival
- `retention_config: Option<RetentionConfig>` field on `KernelConfig` (default None)
- Constants: `DEFAULT_RETENTION_DAYS = 90`, `DEFAULT_MAX_SIZE_BYTES = 10_737_418_240`

**Commits:**
- `f4d9377` -- test(09-01): add failing retention tests (RED phase)
- `82c5848` -- feat(09-01): implement receipt retention with time and size rotation

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed missing `dpop_required` field in ToolGrant initializers workspace-wide**

- **Found during:** Task 1, RED phase (compilation errors)
- **Issue:** Phase 09-02 added `dpop_required: Option<bool>` to the `ToolGrant` struct in arc-core, but many existing struct initializers throughout the workspace did not include this field, causing compilation failures
- **Fix:** Added `dpop_required: None` to all affected ToolGrant initializer sites across authority.rs, transport.rs, lib.rs (kernel), edge.rs (mcp-adapter), full_flow.rs (e2e), integration.rs (guards), vector_fixtures.rs, capability.rs (bindings-core), compiler.rs (policy), monetary_types.rs, forward_compat.rs
- **Files modified:** 11 files (many already partially fixed by the 09-02 agent in an earlier run)
- **Commit:** `f4d9377` (RED phase commit)

## Tests

Four new retention tests in `crates/arc-kernel/tests/retention.rs`:

| Test | What it verifies |
|------|-----------------|
| `retention_rotates_at_time_boundary` | Receipts before cutoff archived; after cutoff remain live |
| `retention_rotates_at_size_boundary` | Size threshold triggers rotate_if_needed |
| `archived_receipt_verifies_against_checkpoint` | Archived receipts verify against Merkle checkpoint roots in archive DB |
| `archive_preserves_checkpoint_rows` | Batch 1 checkpoint in archive; batch 2 checkpoint stays in live DB |

## Compliance Mapping

- **COMP-03:** `retention_config` on `KernelConfig` provides configurable `retention_days` and `max_size_bytes`; rotation archives to a separate SQLite file
- **COMP-04:** `archived_receipt_verifies_against_checkpoint` test demonstrates that archived receipts verify against stored Merkle checkpoint roots in the archive database

## Self-Check: PASSED

**Files exist:**
- `/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/receipt_store.rs` -- contains RetentionConfig, db_size_bytes, archive_receipts_before, rotate_if_needed
- `/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/tests/retention.rs` -- 4 retention tests

**Commits exist:**
- `f4d9377` -- RED phase tests (verified in git log)
- `82c5848` -- GREEN phase implementation (verified in git log)

**Tests pass:**
- `cargo test -p arc-kernel -- retention` -- 4 passed, 0 failed
- `cargo test --workspace` -- all test suites passed (no regressions)
- `cargo clippy --workspace -- -D warnings` -- clean
