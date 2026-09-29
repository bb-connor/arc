# SQLite authorization performance and retention diagnosis implementation plan

> **For agentic workers:** Use superpowers:executing-plans inline in the existing isolated worktree. This batch is already authorized.

**Goal:** Complete Packet 9.3/9.5 with measured authorization improvements and investigate historical retention issue 1045 through its original workload, repairing only demonstrated causes.

**Architecture:** Cache compiled SQL at the owning connection, never authorization results. Retain a validated hold within its existing write transaction instead of querying it twice. Diagnose receipt writer/checkpointer/rotation ownership with bounded process observations and preserve exact failures.

**Tech Stack:** Rust, rusqlite, SQLite WAL, Criterion, existing receipt VFS diagnostics.

**Spec:** docs/security/engineering-standard.md rules 13.1-13.10; docs/superpowers/plans/2026-09-26-security-engineering-excellence.md Packet 9.3/9.5; docs/reviews/2026-09-28-remaining-security-work.md items 5 and 6; issue 1045.

## Global constraints

- Preserve authority fences, transaction snapshots, signed bytes, rollback and recovery semantics. No authorization-result cache, connection-pool migration or compatibility layer.
- Keep schema, migration and reporting SQL outside the hot statement cache.
- Measure the same populated workload before and after; state hardware/profile and scope. A receipt append result does not qualify authorization.
- Preserve preexisting output/. Local commits only, no push, merge or issue mutation.
- Inline implementation, focused checks and one final fresh review. Do not repeat expensive passing campaigns without a changed boundary.

## Review focus

- Cached statements release bindings and snapshots before commit, rollback, schema work or archive detach.
- A cached statement still sees externally changed rows and current authorization fences.
- Reusing a hold cannot skip captured-state, amount, identity, authority or replay checks.
- A retention timeout preserves accepted-work ownership and cannot be reported as cancellation.
- The historical stalled process and the current diagnostic must not be conflated; a nonreproduction does not establish a root cause.

### Task 1: Measured statement caching and duplicate hold read removal

**Files:** chio-store-sqlite budget_store/{store.rs,trait_impl.rs,tests.rs,tests/*}, measured admission/security read owners, connection initialization, benches/store_authorization_path.rs and its support modules.

**Interfaces:** Consume existing public authorization/store APIs and scoped SQLite transactions. Produce bounded per-connection prepared statement caches and one validated hold per mutation; no new public API required.

- [x] Capture before measurements and SQL preparation/read counts on populated authorization paths.
- [x] Write a regression observing redundant hold reads and current-row/authority behavior; run the relevant failing assertion before repair.
- [x] Cache measured hot reads with explicit connection capacity and remove redundant hold reads within the original transaction.
- [x] Run focused budget, replay, authority and connection recovery tests plus before/after measurements. Expected: preserved refusal/rollback behavior, fewer compilations/reads, recorded latency delta.
- [x] Commit implementation and evidence.

### Task 2: Original retention workload and demonstrated liveness repair (incomplete)

**Files:** receipt_store/tests/retention.rs, receipt_store/tests/retention_liveness.rs, tests/receipt_retention_liveness.rs and its diagnostic support, actual implicated writer/checkpointer/rotation owner, batch evidence.

**Interfaces:** Consume the original issue source/configuration and existing public receipt APIs. Produce a reproducible ownership diagnosis, a minimal repair where demonstrated, and a bounded regression/qualification artifact.

- [x] Recover exact historical source, runner configuration and original failure evidence; compare against current ownership.
- [x] Run the original 256-case workload under a bounded process/watchdog with explicit seed and slow syncs. Result: 242 cases complete before the overall 900-second limit; progress continued. Thread wait states captured, stack attachment denied. This diagnostic did not reproduce the historical stall.
- [ ] Write a deterministic regression for any demonstrated cause, observe failure, then repair the responsible owner. Do not invent a cause if the evidence only establishes nonreproduction.
- [x] Qualify the diagnostic completion correction and existing deterministic ownership checks. Preserve terminal counts, receipt partition/health assertions and the remaining diagnostic gap.
- [ ] Complete the full 256-case slow-sync qualification after supported ownership/stack capture is established.
- [x] Commit the diagnostic and evidence; reconcile the roadmap and propose the next substantive batch. No production receipt repair is claimed.

Status: Packet 9.3/9.5 is locally implemented and measured. Retention issue 1045
root cause/repair and the complete 256-case slow-sync gate remain open. See
[execution evidence](../../reviews/2026-09-29-sqlite-performance-retention-execution.md).
