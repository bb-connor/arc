---
phase: 373-wasm-runtime-host-foundation
plan: 02
subsystem: wasm-runtime
tags: [wasmtime, wasm, arc_alloc, arc_deny_reason, guest-exports, capability-probing]

# Dependency graph
requires:
  - phase: 373-wasm-runtime-host-foundation (plan 01)
    provides: WasmHostState, shared Arc<Engine>, host function registration, Store<WasmHostState> evaluate() flow
provides:
  - arc_alloc guest export probing with in-bounds validation and offset-0 fallback
  - arc_deny_reason guest export probing with JSON GuestDenyResponse parsing and legacy fallback
  - read_structured_deny_reason function for JSON/UTF-8 deny reason extraction
  - 8 WAT-based unit tests covering all arc_alloc and arc_deny_reason code paths
affects: [374-wasm-security-enrichment, 375-wasm-manifest-wiring]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Optional guest export probing via get_typed_func().ok() with graceful fallback"
    - "Pointer validation: non-negative, ptr+len within memory.data_size()"
    - "Structured deny reason protocol: arc_deny_reason(buf_ptr, buf_len) -> bytes_written"
    - "JSON-first parsing with UTF-8 fallback for deny reasons"
    - "Hex-escaped WAT data segments for embedding JSON in test fixtures"

key-files:
  created: []
  modified:
    - crates/arc-wasm-guards/src/runtime.rs

key-decisions:
  - "arc_alloc validation uses saturating_add for overflow-safe bounds checking"
  - "arc_deny_reason reuses the same 64K buffer region as legacy deny reason (avoids allocating a separate region)"
  - "read_structured_deny_reason tries JSON GuestDenyResponse first, falls back to plain UTF-8 string"
  - "All probing errors fall back silently (no tracing warn on absent exports, only on failed/OOB calls)"

patterns-established:
  - "Optional export probing: get_typed_func().ok() returns None when export absent, Some when present"
  - "Guest allocator contract: arc_alloc(size) -> ptr, host validates ptr before use"
  - "Structured deny protocol: arc_deny_reason(buf_ptr, buf_len) -> i32 bytes_written"

requirements-completed: [WGRT-06, WGRT-07]

# Metrics
duration: 14min
completed: 2026-04-14
---

# Phase 373 Plan 02: Guest Export Detection Summary

**arc_alloc guest allocator probing with offset-0 fallback and arc_deny_reason structured deny reason extraction with legacy NUL-string fallback**

## Performance

- **Duration:** 14 min
- **Started:** 2026-04-14T20:53:25Z
- **Completed:** 2026-04-14T21:07:44Z
- **Tasks:** 2
- **Files modified:** 1

## Accomplishments
- Added arc_alloc guest export probing to evaluate(): when present and returning a valid in-bounds pointer, the host writes request data at the allocator-returned address instead of offset 0
- Added arc_deny_reason guest export probing after VERDICT_DENY: when present, calls guest function to get structured JSON deny reason with plain UTF-8 fallback
- Implemented pointer validation with overflow-safe bounds checking (saturating_add, non-negative check, ptr+len <= mem_size)
- Added 8 WAT-based unit tests covering all code paths: valid alloc, no alloc, OOB alloc, negative alloc, structured deny, legacy deny, invalid deny, no deny
- All 32 crate tests pass, clippy clean, zero workspace regressions

## Task Commits

Each task was committed atomically (TDD: test then feat):

1. **Task 1: arc_alloc guest export detection with offset-0 fallback**
   - `b2b8dca` (test) - failing arc_alloc tests
   - `c55673e` (feat) - arc_alloc probing implementation
2. **Task 2: arc_deny_reason guest export detection with offset-64K fallback**
   - `21ec6f7` (test) - failing arc_deny_reason tests
   - `de0d987` (feat) - arc_deny_reason probing implementation

## Files Created/Modified
- `crates/arc-wasm-guards/src/runtime.rs` - Added arc_alloc probing before memory write, arc_deny_reason probing after VERDICT_DENY, read_structured_deny_reason function, 8 WAT-based tests

## Decisions Made
- arc_alloc validation uses saturating_add to prevent overflow when checking pointer bounds; a negative i32 interpreted as unsigned wraps to a very large value, so the >= 0 check catches it first
- arc_deny_reason reuses the same 64K offset and 4096-byte buffer region as the legacy deny reason path, avoiding additional memory region negotiation
- read_structured_deny_reason attempts JSON GuestDenyResponse parsing first, then falls back to interpreting the bytes as a plain UTF-8 string (trimming trailing NUL bytes)
- Absent exports produce no log noise (no tracing::warn when get_typed_func returns None); only failed or OOB calls log warnings

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed WAT string escaping for JSON data segments**
- **Found during:** Task 2 (arc_deny_reason test authoring)
- **Issue:** WAT data segment syntax does not support embedded double quotes in string literals; the JSON `{"reason":"blocked by policy"}` caused a WAT parse error
- **Fix:** Used hex-escaped byte sequences (`\xx` format) in the WAT data segment to encode the JSON without conflicting with WAT string delimiters
- **Files modified:** crates/arc-wasm-guards/src/runtime.rs (test only)
- **Verification:** WAT module compiles and test passes
- **Committed in:** `de0d987` (Task 2 commit)

**2. [Rule 1 - Bug] Fixed &mut Store reborrow in read_structured_deny_reason**
- **Found during:** Task 2 (arc_deny_reason implementation)
- **Issue:** Passing `store: &mut Store` to `reason_fn.call(store, ...)` moved the mutable reference, preventing subsequent `memory.read(store, ...)` call
- **Fix:** Used explicit reborrow `&mut *store` for the call to allow the reference to be reused
- **Files modified:** crates/arc-wasm-guards/src/runtime.rs
- **Verification:** Compiles and all tests pass
- **Committed in:** `de0d987` (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (1 blocking, 1 bug)
**Impact on plan:** Both auto-fixes were mechanical/syntactic. No scope creep.

## Issues Encountered
None beyond the auto-fixed deviations above.

## User Setup Required
None -- no external service configuration required.

## Next Phase Readiness
- Guest export probing (arc_alloc + arc_deny_reason) is complete and tested
- The evaluate() flow now supports both simple guests (offset 0, NUL string) and sophisticated guests (allocator, structured deny)
- Ready for Phase 374 (WASM security enrichment) and Phase 375 (manifest wiring)

---
*Phase: 373-wasm-runtime-host-foundation*
*Completed: 2026-04-14*
