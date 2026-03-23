---
phase: 11-siem-integration
plan: "01"
subsystem: pact-siem
tags: [siem, exporter, dlq, cursor-pull, sqlite, reqwest, kernel-isolation]
dependency_graph:
  requires: [pact-core]
  provides: [pact-siem crate, Exporter trait, SiemEvent, DeadLetterQueue, ExporterManager, SiemConfig, siem feature flag in pact-cli]
  affects: [Cargo.toml workspace members, crates/pact-cli/Cargo.toml features]
tech_stack:
  added: [reqwest 0.12 (rustls-tls, json), wiremock 0.6 (dev), rusqlite (bundled, workspace)]
  patterns: [Pin<Box<dyn Future>> for dyn-compatible async trait, per-poll rusqlite connection in spawn_blocking, seq-based cursor without disk persistence, bounded DLQ with drop-oldest overflow]
key_files:
  created:
    - crates/pact-siem/Cargo.toml
    - crates/pact-siem/src/lib.rs
    - crates/pact-siem/src/event.rs
    - crates/pact-siem/src/exporter.rs
    - crates/pact-siem/src/dlq.rs
    - crates/pact-siem/src/manager.rs
    - crates/pact-siem/src/exporters/mod.rs
  modified:
    - Cargo.toml (workspace members: added crates/pact-siem)
    - crates/pact-cli/Cargo.toml (optional pact-siem dep, siem feature flag)
decisions:
  - Exporter trait uses Pin<Box<dyn Future>> (not impl Trait) for dyn compatibility -- required for Box<dyn Exporter> in ExporterManager
  - Cursor is not persisted to disk -- restart re-exports from seq=0, acceptable because Splunk HEC and Elasticsearch handle duplicates idempotently
  - Per-poll rusqlite connection opened read-only in spawn_blocking -- avoids holding read lock across poll intervals
  - pact-siem depends on pact-core only, NOT pact-kernel -- kernel TCB stays free of HTTP client (reqwest) transitive deps
  - DLQ drops oldest entry on overflow with tracing::error -- bounded memory, observable
metrics:
  duration_seconds: 208
  completed_date: "2026-03-23"
  tasks_completed: 2
  files_created: 7
  files_modified: 2
---

# Phase 11 Plan 01: pact-siem Crate Foundation Summary

**One-liner:** pact-siem crate with Exporter trait (dyn-compatible via Pin<Box<dyn Future>>), SiemEvent, bounded DeadLetterQueue, and ExporterManager seq-cursor-pull loop using read-only rusqlite in spawn_blocking.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Create pact-siem crate with core types and Cargo integration | 5fc013d | Cargo.toml, pact-cli/Cargo.toml, pact-siem/{Cargo.toml,lib.rs,event.rs,exporter.rs,dlq.rs,exporters/mod.rs} |
| 2 | Implement ExporterManager cursor-pull loop with retry and DLQ | 43711cd | crates/pact-siem/src/manager.rs |

## Verification Results

1. `cargo build -p pact-siem` -- PASS
2. `cargo clippy -p pact-siem -- -D warnings` -- PASS (no warnings)
3. `cargo tree -p pact-kernel | grep reqwest` -- PASS (empty -- kernel isolation verified)
4. `cargo build -p pact-cli --features siem` -- PASS

## Key Decisions

### Exporter Trait: Pin<Box<dyn Future>> for Dyn Compatibility

**Context:** The plan specified "native async-in-trait, no async_trait crate -- Rust 1.93 supports this". Rust 1.93 supports `async fn` in traits for static dispatch, but `impl Trait` return types are not dyn-compatible and prevent `Box<dyn Exporter>`.

**Decision:** Use `Pin<Box<dyn Future<Output = Result<usize, ExportError>> + Send + 'a>>` as the return type. This is dyn-compatible, enables `Vec<Box<dyn Exporter>>` in ExporterManager, and requires no external crates. Implementors box their futures with `Box::pin(async move { ... })`.

**Type alias:** `ExportFuture<'a>` exported from `pact_siem::exporter` for implementor ergonomics.

### Cursor Not Persisted to Disk

**Context:** On restart, the cursor resets to 0 and re-exports all receipts from the beginning.

**Decision:** This is acceptable because Splunk HEC uses timestamp-based deduplication and Elasticsearch uses `_id` upsert. Both backends handle idempotent re-export without data corruption. Cursor persistence can be added in a future phase if needed.

### Per-Poll rusqlite Connection in spawn_blocking

**Context:** SQLite blocking operations must not run on the async executor thread.

**Decision:** Open a fresh read-only connection per poll cycle inside `tokio::task::spawn_blocking`. This is slightly less efficient than a persistent connection but avoids holding a read lock across poll intervals. WAL-mode SQLite readers do not block kernel writers.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Exporter trait dyn incompatibility with impl Trait return**

- **Found during:** Task 1 -- first cargo build attempt
- **Issue:** Plan specified `impl std::future::Future<Output = ...> + Send` as the return type in the Exporter trait. Rust's `impl Trait` in trait methods is not dyn-compatible, making `Box<dyn Exporter>` impossible (E0038).
- **Fix:** Changed return type to `Pin<Box<dyn Future<Output = Result<usize, ExportError>> + Send + 'a>>` with a `ExportFuture<'a>` type alias for ergonomics. Exported `ExportFuture` from crate root.
- **Files modified:** `crates/pact-siem/src/exporter.rs`, `crates/pact-siem/src/lib.rs`
- **Commit:** Part of 5fc013d (corrected before commit)

## Self-Check: PASSED

All created files exist on disk. Both task commits (5fc013d, 43711cd) verified in git log.
