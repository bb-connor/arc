---
phase: 382-guest-sdk-core
plan: 02
subsystem: wasm-sdk
tags: [wasm, guest-sdk, host-bindings, abi-glue, ffi, deny-reason]

# Dependency graph
requires:
  - phase: 382-guest-sdk-core
    provides: "arc-guard-sdk crate with GuardRequest, GuardVerdict, GuestDenyResponse types and Vec-based allocator"
provides:
  - "Typed host function bindings (arc.log, arc.get_config, arc.get_time) with wasm32/native dual compilation"
  - "ABI glue: read_request, encode_verdict, arc_deny_reason export"
  - "Complete prelude re-exporting all guard-author API surfaces"
affects: [383-proc-macro-example-guards]

# Tech tracking
tech-stack:
  added: []
  patterns: [wasm-import-module-ffi, cfg-gated-dual-target, thread-local-deny-reason, serialize-deny-reason-extraction]

key-files:
  created:
    - crates/arc-guard-sdk/src/host.rs
    - crates/arc-guard-sdk/src/glue.rs
  modified:
    - crates/arc-guard-sdk/src/lib.rs

key-decisions:
  - "serialize_deny_reason() extracted as pure-logic function from arc_deny_reason for testability on 64-bit native targets (i32 buf_ptr truncates heap pointers on 64-bit)"
  - "Host function wrappers use #[cfg(target_arch = \"wasm32\")] gating with no-op/default fallbacks for native cargo test"
  - "Thread-local deny reason uses const initializer pattern (RefCell::new(None)) matching alloc.rs convention"

patterns-established:
  - "cfg-gated dual-target: wasm32 calls host FFI, non-wasm32 returns safe defaults for testing"
  - "Extracted serialize helper: untestable extern C functions get a pure-logic inner function for native testing"
  - "Prelude pattern: pub mod prelude re-exports types + host + glue for one-line guard imports"

requirements-completed: [GSDK-03, GSDK-04, GSDK-05]

# Metrics
duration: 7min
completed: 2026-04-14
---

# Phase 382 Plan 02: Host Bindings and ABI Glue Summary

**Typed FFI bindings for arc.log/get_config/get_time host imports plus ABI glue (read_request, encode_verdict, arc_deny_reason) completing the guest SDK surface**

## Performance

- **Duration:** 7 min
- **Started:** 2026-04-14T23:27:32Z
- **Completed:** 2026-04-14T23:35:05Z
- **Tasks:** 3
- **Files modified:** 3

## Accomplishments
- host.rs with #[link(wasm_import_module = "arc")] FFI declarations matching host Linker registrations exactly
- Safe wrappers (log, get_config, get_time) with wasm32-gated implementations and native no-op fallbacks
- glue.rs with read_request (unsafe serde_json::from_slice from linear memory), encode_verdict (VERDICT_ALLOW/DENY + thread-local deny reason), and #[no_mangle] arc_deny_reason export
- lib.rs expanded with complete prelude re-exporting all guard-author API surfaces
- 24 unit tests passing across types, alloc, host, and glue modules; clippy clean; fmt clean

## Task Commits

Each task was committed atomically:

1. **Task 1: Implement typed host function bindings (host.rs)** - `dcb3558` (feat)
2. **Task 2: Implement ABI glue (TDD RED)** - `2be5053` (test)
3. **Task 2: Implement ABI glue (TDD GREEN)** - `4cf5c58` (feat)
4. **Task 3: Update lib.rs with host and glue modules, expand prelude** - `df79110` (feat)

## Files Created/Modified
- `crates/arc-guard-sdk/src/host.rs` - Typed FFI bindings for arc.log, arc.get_config, arc.get_time_unix_secs with safe wrappers
- `crates/arc-guard-sdk/src/glue.rs` - ABI glue: read_request, encode_verdict, arc_deny_reason, thread-local deny reason storage
- `crates/arc-guard-sdk/src/lib.rs` - Module declarations, top-level re-exports, expanded prelude, crate-level docs

## Decisions Made
- Extracted serialize_deny_reason() as a pure-logic helper from arc_deny_reason because the #[no_mangle] extern "C" function takes i32 buf_ptr which truncates 64-bit heap pointers on native test targets, making direct calls segfault. Tests exercise the logic through the extracted function instead.
- Host function wrappers use cfg(target_arch = "wasm32") gating rather than feature flags, matching the pattern used by wasm-bindgen and similar crates.
- clear_deny_reason() gated with #[cfg(test)] since it is only needed for test cleanup and triggers dead_code warning otherwise.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Extracted serialize_deny_reason to avoid native test SIGSEGV**
- **Found during:** Task 2 (glue.rs TDD GREEN phase)
- **Issue:** Plan suggested testing arc_deny_reason by passing heap Vec pointer as i32, but on 64-bit macOS the pointer truncation causes SIGSEGV when arc_deny_reason dereferences the truncated address
- **Fix:** Extracted the serialization logic into serialize_deny_reason() -> Option<Vec<u8>> and tested that instead; the arc_deny_reason function delegates to it
- **Files modified:** crates/arc-guard-sdk/src/glue.rs
- **Verification:** All 8 glue tests pass without SIGSEGV
- **Committed in:** 4cf5c58

**2. [Rule 1 - Bug] Fixed clippy dead_code warning on clear_deny_reason**
- **Found during:** Task 3 (final validation)
- **Issue:** clear_deny_reason() is pub(crate) but only used in #[cfg(test)] module, causing -D dead-code error under clippy
- **Fix:** Added #[cfg(test)] attribute to clear_deny_reason()
- **Files modified:** crates/arc-guard-sdk/src/glue.rs
- **Verification:** cargo clippy -p arc-guard-sdk -- -D warnings passes clean
- **Committed in:** df79110

---

**Total deviations:** 2 auto-fixed (2 bug fixes)
**Impact on plan:** Both fixes were necessary for correctness. The serialize_deny_reason extraction is a minor structural improvement that improves testability without changing the external API. No scope creep.

## Issues Encountered
None

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- The arc-guard-sdk crate now exposes the complete guest-side API surface: types (GuardRequest, GuardVerdict, GuestDenyResponse), allocator (arc_alloc, arc_free), host bindings (log, get_config, get_time), and ABI glue (read_request, encode_verdict, arc_deny_reason)
- Phase 383 (proc macro and example guards) can begin: the #[arc_guard] macro will generate the evaluate export that calls read_request, delegates to the user function, and calls encode_verdict
- Real end-to-end testing (loading .wasm into WasmtimeBackend) will happen in Phase 383

---
*Phase: 382-guest-sdk-core*
*Completed: 2026-04-14*
