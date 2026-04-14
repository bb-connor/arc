---
phase: 382-guest-sdk-core
plan: 01
subsystem: wasm-sdk
tags: [wasm, guest-sdk, serde, allocator, abi, guard]

# Dependency graph
requires:
  - phase: 376-wasm-guard-benchmarks
    provides: "Stable host runtime with benchmarked evaluate pipeline and arc_alloc probing"
provides:
  - "arc-guard-sdk crate with GuardRequest, GuardVerdict, GuestDenyResponse types"
  - "Vec-based guest allocator (arc_alloc, arc_free) matching host ABI"
  - "Prelude module for ergonomic guard authoring imports"
affects: [382-02, 383-proc-macro-example-guards]

# Tech tracking
tech-stack:
  added: [arc-guard-sdk]
  patterns: [guest-abi-mirror-types, vec-thread-local-allocator, prelude-module]

key-files:
  created:
    - crates/arc-guard-sdk/Cargo.toml
    - crates/arc-guard-sdk/src/lib.rs
    - crates/arc-guard-sdk/src/types.rs
    - crates/arc-guard-sdk/src/alloc.rs
  modified:
    - Cargo.toml

key-decisions:
  - "GuardVerdict::Deny uses String (non-optional) for reason because guest guards should always explain denials"
  - "Vec-based allocator with thread-local storage chosen over bump allocator for simplicity and safety"
  - "No dependency on host-side crates (wasmtime, arc-core, arc-kernel, arc-wasm-guards)"

patterns-established:
  - "ABI mirror types: guest SDK types use identical serde annotations to host abi.rs"
  - "Thread-local Vec allocator: arc_alloc pushes Vec into thread-local, arc_free removes by pointer+length match"
  - "Defensive allocator: returns 0 for invalid sizes, silent no-op for invalid free"

requirements-completed: [GSDK-01, GSDK-02]

# Metrics
duration: 6min
completed: 2026-04-14
---

# Phase 382 Plan 01: Guest SDK Core Summary

**Guest-side arc-guard-sdk crate with ABI-identical types (GuardRequest/GuardVerdict/GuestDenyResponse) and Vec-based guest allocator (arc_alloc/arc_free) for WASM guard authoring**

## Performance

- **Duration:** 6 min
- **Started:** 2026-04-14T23:18:56Z
- **Completed:** 2026-04-14T23:25:05Z
- **Tasks:** 3
- **Files modified:** 5

## Accomplishments
- Created arc-guard-sdk crate registered as workspace member with serde + serde_json deps only
- GuardRequest with 10 fields and serde annotations matching host abi.rs exactly (4 skip_serializing_if Option::is_none, 1 skip_serializing_if Vec::is_empty)
- GuardVerdict enum with allow()/deny() convenience constructors and mandatory deny reason
- Vec-based guest allocator with arc_alloc(i32)->i32 and arc_free(i32,i32) as #[no_mangle] pub extern "C" exports
- lib.rs prelude module re-exporting core types for ergonomic guard authoring
- 12 unit tests passing, clippy clean

## Task Commits

Each task was committed atomically:

1. **Task 1: Create arc-guard-sdk crate with Cargo.toml and workspace registration** - `9086729` (feat)
2. **Task 2: Implement GuardRequest, GuardVerdict, and GuestDenyResponse types (TDD)** - `a940b6d` (test/RED), `1dc7741` (feat/GREEN)
3. **Task 3: Implement Vec-based guest allocator and wire up lib.rs (TDD)** - `5f961f1` (test/RED), `0eb4379` (feat/GREEN)

## Files Created/Modified
- `crates/arc-guard-sdk/Cargo.toml` - Crate manifest with serde + serde_json workspace deps
- `crates/arc-guard-sdk/src/lib.rs` - Public API with mod declarations, re-exports, and prelude
- `crates/arc-guard-sdk/src/types.rs` - GuardRequest, GuardVerdict, GuestDenyResponse, VERDICT_ALLOW/DENY constants
- `crates/arc-guard-sdk/src/alloc.rs` - Vec-based guest allocator (arc_alloc, arc_free) with thread-local storage
- `Cargo.toml` - Added arc-guard-sdk to workspace members list

## Decisions Made
- GuardVerdict::Deny uses non-optional String reason (guest guards should always explain denials; host-side Option comes from the arc_deny_reason fallback path)
- Vec-based allocator with thread-local storage chosen for simplicity; each arc_alloc pushes a fresh Vec, arc_free matches by pointer+length
- No host-side crate dependencies to keep the SDK compilable for wasm32-unknown-unknown without pulling in wasmtime or kernel code
- Added PartialEq derive to GuardRequest and GuestDenyResponse for test ergonomics

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed clippy::missing_const_for_thread_local warning**
- **Found during:** Task 3 (alloc.rs implementation)
- **Issue:** Clippy on Rust 1.93 requires `const { ... }` initializer for thread_local
- **Fix:** Changed `RefCell::new(Vec::new())` to `const { RefCell::new(Vec::new()) }`
- **Files modified:** crates/arc-guard-sdk/src/alloc.rs
- **Verification:** cargo clippy -p arc-guard-sdk -- -D warnings passes clean
- **Committed in:** 0eb4379 (part of Task 3 GREEN commit)

---

**Total deviations:** 1 auto-fixed (1 bug fix)
**Impact on plan:** Trivial lint fix required by Rust 1.93 const thread_local. No scope creep.

## Issues Encountered
None

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Types and allocator are ready for Plan 02 to layer host function bindings (arc::log, arc::get_config, arc::get_time) and ABI glue (read_request, encode_verdict, arc_deny_reason)
- Phase 383 (proc macro and example guards) can begin after Plan 02 completes

## Self-Check: PASSED

All 5 created files verified present. All 5 commit hashes verified in git log.

---
*Phase: 382-guest-sdk-core*
*Completed: 2026-04-14*
