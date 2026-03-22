---
phase: 08-core-enforcement
plan: 03
subsystem: pact-guards
tags: [velocity, rate-limiting, token-bucket, guard, kernel]
dependency_graph:
  requires: [pact-kernel Guard trait, pact-core CapabilityToken]
  provides: [VelocityGuard, VelocityConfig, TokenBucket, matched_grant_index on GuardContext]
  affects: [pact-guards, pact-kernel, pact-cli]
tech_stack:
  added: [std::sync::Mutex for synchronous token bucket state]
  patterns: [token bucket algorithm with elapsed-time refill, per-(capability_id, grant_index) keyed buckets]
key_files:
  created:
    - crates/pact-guards/src/velocity.rs
  modified:
    - crates/pact-guards/src/lib.rs
    - crates/pact-kernel/src/lib.rs
    - crates/pact-guards/src/pipeline.rs
    - crates/pact-guards/src/mcp_tool.rs
    - crates/pact-guards/src/secret_leak.rs
    - crates/pact-guards/src/patch_integrity.rs
    - crates/pact-guards/src/path_allowlist.rs
    - crates/pact-cli/src/policy.rs
    - crates/pact-cli/src/trust_control.rs
    - crates/pact-kernel/src/receipt_store.rs
decisions:
  - "Use elapsed-time refill in try_consume rather than a background thread to keep the guard synchronous and lock-free between invocations"
  - "matched_grant_index defaults to None in all existing GuardContext construction sites; population happens in plan 08-04"
  - "RemoteBudgetStore::try_charge_cost returns Ok(true) as a pass-through stub; cost tracking deferred to authority node"
metrics:
  duration: 7 minutes
  tasks_completed: 1
  files_created: 1
  files_modified: 10
  completed_date: "2026-03-22"
---

# Phase 08 Plan 03: VelocityGuard Implementation Summary

VelocityGuard with synchronous Mutex-wrapped token buckets, rate limiting per (capability_id, grant_index) with elapsed-time refill.

## What Was Built

### VelocityGuard (crates/pact-guards/src/velocity.rs)

- `TokenBucket` (private): capacity/tokens/refill_rate/last_refill struct with `try_consume` that refills via elapsed time
- `VelocityConfig`: max_invocations_per_window, max_spend_per_window, window_secs, burst_factor
- `VelocityGuard`: two `Mutex<HashMap<(String, usize), TokenBucket>>` fields (invocation + spend buckets), keyed by (capability_id, grant_index)
- `impl Guard for VelocityGuard`: name returns "velocity", evaluate checks invocation limit then spend limit, returns `Verdict::Deny` on rate exceeded (never `Err` for rate limiting)

### GuardContext Extension (crates/pact-kernel/src/lib.rs)

Added `pub matched_grant_index: Option<usize>` field. Updated the single kernel-internal construction site to include `matched_grant_index: None`. All 10 external construction sites in pact-guards and pact-cli also updated.

## Tests (10 passing)

- `guard_name_is_velocity`: name() returns "velocity"
- `velocity_config_defaults_unlimited`: None fields = unlimited
- `unlimited_config_always_allows`: 100 requests pass with default config
- `allows_requests_up_to_limit`: 5 requests pass when limit=5
- `denies_request_exceeding_limit`: 6th request denied when limit=5
- `tokens_refill_after_window`: 1.1s sleep refills 1-second window bucket
- `separate_buckets_for_different_grant_indices`: grant 0 exhausted, grant 1 fresh
- `separate_buckets_for_different_capability_ids`: cap-a exhausted, cap-b unaffected
- `returns_verdict_deny_not_err_when_rate_limited`: result is Ok(Verdict::Deny), not Err
- `spend_velocity_allows_up_to_limit`: 3 spend units pass, 4th denied

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed pre-existing pact-cli RemoteBudgetStore missing try_charge_cost**
- **Found during:** Task 1 (compilation check)
- **Issue:** `BudgetStore` trait gained `try_charge_cost` in an earlier plan but `RemoteBudgetStore` in pact-cli was not updated. Also two `BudgetUsageRecord` initializers missing the new `total_cost_charged` field.
- **Fix:** Added stub `try_charge_cost` returning `Ok(true)` (pass-through, authority node handles cost). Added `total_cost_charged: 0` to two struct initializers.
- **Files modified:** `crates/pact-cli/src/trust_control.rs`
- **Commit:** f3d254a

**2. [Rule 3 - Blocking] Fixed pre-existing receipt_store.rs serde_json::Error::custom usage**
- **Found during:** Task 1 (test compilation)
- **Issue:** `serde_json::Error::custom` requires `serde::de::Error` trait in scope. Two call sites used it incorrectly.
- **Fix:** Replaced with `ReceiptStoreError::CryptoDecode(e.to_string())` and `ReceiptStoreError::Canonical(e.to_string())` which are the correct purpose-built variants already defined in the error enum.
- **Files modified:** `crates/pact-kernel/src/receipt_store.rs`
- **Commit:** f3d254a

## Commits

| Hash | Description |
|------|-------------|
| f3d254a | feat(08-03): implement VelocityGuard with synchronous token bucket rate limiting |

## Self-Check: PASSED

- FOUND: crates/pact-guards/src/velocity.rs
- FOUND: crates/pact-guards/src/lib.rs
- FOUND: crates/pact-kernel/src/lib.rs
- FOUND: commit f3d254a
