---
phase: 305-async-kernel-migration
plan: 01
subsystem: kernel
tags:
  - rust
  - kernel
  - concurrency
  - interior-mutability
requires: []
provides:
  - interior-mutability-backed runtime state inside `ArcKernel`
  - shared-access session/store/log helpers that remove exclusive kernel borrowing from runtime operations
  - shared receipt/checkpoint persistence paths over lock-protected stores
affects:
  - phase-305-02
  - phase-305-03
  - phase-306
tech-stack:
  added: []
  patterns:
    - `RwLock<HashMap<SessionId, Session>>` for runtime session state
    - `Mutex<Box<dyn ...>>` wrappers for runtime stores
    - atomic counters for session IDs and checkpoint sequencing
key-files:
  created:
    - .planning/phases/305-async-kernel-migration/305-01-SUMMARY.md
  modified:
    - crates/arc-kernel/src/kernel/mod.rs
    - crates/arc-kernel/src/kernel/session_ops.rs
    - crates/arc-kernel/src/kernel/responses.rs
    - crates/arc-kernel/src/session.rs
key-decisions:
  - "Moved mutable runtime state into `ArcKernel` itself instead of introducing an actor façade, because the milestone explicitly requires interior mutability for session state, receipt logs, and runtime stores."
  - "Kept builder-time registration and setter APIs on `&mut self` while converting runtime/session operations to `&self`, preserving setup-time clarity without serializing steady-state use."
  - "Returned owned session and receipt-log snapshots rather than exposing long-lived lock guards through the public API."
patterns-established:
  - "Shared-state kernels can keep trait-object stores single-owner but concurrency-safe by wrapping them in `Mutex<Box<dyn Store>>` and routing access through narrow helper closures."
  - "Session-scoped APIs that formerly returned borrowed internals should prefer owned snapshots or closure-based access once runtime state moves behind locks."
requirements-completed:
  - ASYNC-01
  - ASYNC-02
duration: 28 min
completed: 2026-04-13
---

# Phase 305 Plan 01: Kernel Interior Mutability Summary

**`ArcKernel` runtime state now lives behind synchronization primitives, session and receipt operations run on `&self`, and the kernel compiles cleanly without the old exclusive-borrow model**

## Performance

- **Duration:** 28 min
- **Completed:** 2026-04-13
- **Files modified:** 4

## Accomplishments

- Converted runtime-owned mutable kernel fields to shared primitives:
  `sessions` now use `RwLock`, receipt logs and runtime stores use `Mutex`, and
  session/checkpoint counters use atomics.
- Added shared-access helpers in `crates/arc-kernel/src/kernel/mod.rs` for
  session reads/writes and store access so runtime code no longer reaches into
  mutable fields directly.
- Moved session operations, receipt persistence, checkpoint triggers, budget
  charge bookkeeping, and revocation checks onto `&self`.
- Made `Session`, its inflight/subscription/terminal registries, and receipt
  logs cloneable so callers can consume safe snapshots instead of borrowed
  lock-backed internals.

## Verification

- `cargo check -p arc-kernel`

## Decisions Made

- Chose direct interior mutability inside `ArcKernel` rather than an external
  actor handle so the milestone honestly removes exclusive borrowing from the
  kernel's own state.
- Preserved build-time mutability for registration/configuration APIs because
  those calls are setup-only and do not block steady-state concurrency.
- Treated owned session/receipt snapshots as the compatibility boundary for
  tests and downstream readers instead of leaking lock guards.

## Deviations from Plan

None.

## Next Phase Readiness

- `305-01` is complete and the kernel's runtime state no longer depends on
  `&mut self`.
- `305-02` can now flip the public raw tool-call entrypoint to async `&self`
  while keeping a narrow sync compatibility path for legacy callers.

---
*Phase: 305-async-kernel-migration*
*Completed: 2026-04-13*
