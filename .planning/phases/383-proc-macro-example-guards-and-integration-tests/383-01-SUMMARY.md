---
phase: 383-proc-macro-example-guards-and-integration-tests
plan: 01
subsystem: sdk
tags: [proc-macro, wasm, guard-sdk, code-generation, abi]

requires:
  - phase: 382-guard-sdk-guest-side-types-and-allocator
    provides: "arc-guard-sdk crate with types, alloc, glue, host modules"
provides:
  - "#[arc_guard] proc-macro attribute that generates full WASM guard ABI surface"
  - "arc-guard-sdk-macros crate added to workspace"
affects: [383-02 example guards, 383-03 integration tests, arc-guard-sdk consumers]

tech-stack:
  added: [syn 2, quote 1, proc-macro2 1]
  patterns: [proc-macro attribute for ABI generation, path-reference code generation]

key-files:
  created:
    - crates/arc-guard-sdk-macros/Cargo.toml
    - crates/arc-guard-sdk-macros/src/lib.rs
  modified:
    - Cargo.toml

key-decisions:
  - "Proc-macro crate has zero runtime dependency on arc-guard-sdk; generates code referencing arc_guard_sdk::* paths resolved at the call site"
  - "User function renamed to __arc_guard_user_{name} to avoid collision with generated extern C evaluate entry point"
  - "Generated evaluate function uses match on read_request result with VERDICT_DENY on Err for fail-closed semantics"

patterns-established:
  - "ABI code generation via proc-macro: #[arc_guard] eliminates ~20 lines of manual boilerplate per guard"
  - "Re-export pattern: pub use arc_guard_sdk::alloc::{arc_alloc, arc_free} brings allocator exports to crate root"

requirements-completed: [GSDK-06]

duration: 2min
completed: 2026-04-14
---

# Phase 383 Plan 01: Proc-Macro Crate Summary

**#[arc_guard] proc-macro attribute that generates evaluate ABI entry, allocator re-exports, and deny-reason glue from a single user function**

## Performance

- **Duration:** 2 min
- **Started:** 2026-04-14T23:51:13Z
- **Completed:** 2026-04-14T23:53:08Z
- **Tasks:** 1
- **Files modified:** 3 (2 created, 1 modified)

## Accomplishments
- Created arc-guard-sdk-macros proc-macro crate with #[arc_guard] attribute
- Macro generates extern "C" evaluate entry point, arc_alloc/arc_free re-exports, and arc_deny_reason re-export
- Fail-closed semantics: invalid request deserialization returns VERDICT_DENY
- Builds clean under workspace clippy lints (unwrap_used=deny, expect_used=deny)

## Task Commits

Each task was committed atomically:

1. **Task 1: Create arc-guard-sdk-macros crate with #[arc_guard] proc macro** - `100c137` (feat)

## Files Created/Modified
- `crates/arc-guard-sdk-macros/Cargo.toml` - Proc-macro crate manifest with syn/quote/proc-macro2 deps
- `crates/arc-guard-sdk-macros/src/lib.rs` - #[arc_guard] attribute macro implementation
- `Cargo.toml` - Added arc-guard-sdk-macros to workspace members

## Decisions Made
- Proc-macro crate generates path references (arc_guard_sdk::*) rather than depending on arc-guard-sdk at compile time, following standard proc-macro patterns
- User function renamed to __arc_guard_user_{name} to avoid symbol collision with the generated extern "C" evaluate export
- Match-based error handling in generated code (no unwrap/expect) to comply with workspace lints

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Proc-macro crate is ready for consumption by example guards in plan 02
- Guards can now use `#[arc_guard] fn evaluate(req: GuardRequest) -> GuardVerdict` instead of manual ABI boilerplate

---
*Phase: 383-proc-macro-example-guards-and-integration-tests*
*Completed: 2026-04-14*
