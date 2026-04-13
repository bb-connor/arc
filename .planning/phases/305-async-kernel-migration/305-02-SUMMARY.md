---
phase: 305-async-kernel-migration
plan: 02
subsystem: kernel
tags:
  - rust
  - kernel
  - async
  - compatibility
requires:
  - 305-01
provides:
  - async public raw tool-call API on `ArcKernel`
  - synchronous compatibility wrapper for legacy sync callers and tests
  - downstream compile compatibility for CLI, MCP edge, and adjacent test crates
affects:
  - phase-305-03
  - phase-306
tech-stack:
  added: []
  patterns:
    - async public API over a shared-state sync core
    - narrow `*_blocking` compatibility shim for sync consumers
    - downstream test-call migration without transport rewrites
key-files:
  created:
    - .planning/phases/305-async-kernel-migration/305-02-SUMMARY.md
  modified:
    - crates/arc-kernel/src/kernel/mod.rs
    - crates/arc-kernel/src/kernel/session_ops.rs
    - crates/arc-cli/src/cli/session.rs
    - crates/arc-guards/tests/integration.rs
    - crates/arc-a2a-adapter/src/tests/all.rs
key-decisions:
  - "Implemented `ArcKernel::evaluate_tool_call` as the new async public entrypoint while keeping a synchronous `evaluate_tool_call_blocking` shim over the same shared-state core."
  - "Left `arc-mcp-edge` on its existing synchronous session-operation path because it already routes through shared `&self` session APIs and did not require a transport rewrite in this phase."
  - "Updated sync-only test and CLI callers to the blocking shim instead of forcing async runtime scaffolding through every older harness."
patterns-established:
  - "When a core API flips async but the implementation is still sync internally, keep the sync core private and expose a thin async wrapper plus a temporary blocking shim for legacy surfaces."
requirements-completed:
  - ASYNC-01
  - ASYNC-03
duration: 19 min
completed: 2026-04-13
---

# Phase 305 Plan 02: Async API Migration Summary

**The raw kernel tool-call API is now async on `&self`, the legacy sync path is contained to one blocking shim, and downstream compile surfaces stay stable without re-serializing the kernel**

## Performance

- **Duration:** 19 min
- **Completed:** 2026-04-13
- **Files modified:** 5

## Accomplishments

- Changed `ArcKernel::evaluate_tool_call` into an async public API taking
  `&self`.
- Added `ArcKernel::evaluate_tool_call_blocking` as the narrow synchronous
  compatibility path over the same shared-state implementation.
- Redirected session-backed tool-call routing inside `session_ops.rs` to the
  shared sync core so session operations still work without exclusive kernel
  borrows.
- Updated sync-only CLI and test callers to the blocking shim while leaving
  `arc-mcp-edge` on the shared `evaluate_session_operation` path.

## Verification

- `cargo check -p arc-kernel -p arc-mcp-edge -p arc-cli -p arc-control-plane`
- `cargo test --no-run -p arc-kernel -p arc-guards -p arc-a2a-adapter -p arc-cli -p arc-mcp-edge`

## Decisions Made

- Kept the sync core private so the public async signature could land without a
  full transport/runtime rewrite in the same phase.
- Avoided touching `arc-mcp-edge` runtime behavior unnecessarily because its
  session-backed path already benefited from the `&self` migration in
  `session_ops.rs`.
- Scoped the compatibility surface to a single blocking wrapper instead of
  preserving multiple public sync variants.

## Deviations from Plan

### Auto-fixed Issues

**1. Additional sync-only raw callers existed in adjacent test crates**
- **Found during:** downstream compile validation
- **Issue:** `arc-guards`, `arc-a2a-adapter`, and CLI session tests still
  called the old synchronous raw API directly.
- **Fix:** Migrated those harnesses to `evaluate_tool_call_blocking` rather
  than proliferating async test scaffolding.
- **Verification:** `cargo test --no-run -p arc-kernel -p arc-guards -p arc-a2a-adapter -p arc-cli -p arc-mcp-edge`

## Next Phase Readiness

- `305-02` is complete and the public raw API now matches the milestone's
  async `&self` requirement.
- `305-03` can focus entirely on concurrent-evaluation proof and the full phase
  verification matrix.

---
*Phase: 305-async-kernel-migration*
*Completed: 2026-04-13*
