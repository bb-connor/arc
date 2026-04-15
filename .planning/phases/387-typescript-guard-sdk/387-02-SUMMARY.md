---
phase: 387-typescript-guard-sdk
plan: 02
subsystem: testing
tags: [typescript, wasm, component-model, integration-test, wasmtime, jco, dual-mode]

# Dependency graph
requires:
  - phase: 387-typescript-guard-sdk
    provides: "TypeScript guard SDK with compiled tool-gate.wasm (11 MiB Component Model binary)"
  - phase: 386-wit-guard-component-model
    provides: "ComponentBackend and dual-mode create_backend() with format auto-detection"
provides:
  - "Rust integration tests proving TS-compiled WASM guard loads and evaluates correctly in host"
  - "Documented pattern for handling oversized Component Model binaries (raised max_module_size)"
affects: [guard-sdk-docs, ci-pipeline, future-sdk-languages]

# Tech tracking
tech-stack:
  added: []
  patterns: ["ComponentBackend::with_limits() for jco-compiled guards exceeding 10 MiB default", "load_ts_guard_wasm() helper with build instructions in panic message"]

key-files:
  created:
    - crates/arc-wasm-guards/tests/ts_guard_integration.rs
  modified: []

key-decisions:
  - "ComponentBackend::with_limits(16 MiB memory, 15 MiB module) instead of create_backend() default because jco output is 11 MiB"
  - "Test explicitly verifies create_backend() rejects the oversized module, then loads via ComponentBackend with raised limits"
  - "1B fuel limit (vs 1M for core modules) because SpiderMonkey-based components consume more fuel per evaluate call"

patterns-established:
  - "TS SDK integration test pattern: load_ts_guard_wasm() from packages/sdk/arc-guard-ts/dist/, ComponentBackend with raised limits, same verdict assertions as Rust guard"
  - "Module-size awareness: jco componentize output embeds SpiderMonkey (~11 MiB); any JS/TS compiled guard needs raised max_module_size"

requirements-completed: [TSDK-04]

# Metrics
duration: 7min
completed: 2026-04-14
---

# Phase 387 Plan 02: TypeScript Guard Host Integration Tests Summary

**Rust integration tests proving TS-compiled WASM guard loads in host dual-mode runtime with correct Allow/Deny verdicts**

## Performance

- **Duration:** 7 min
- **Started:** 2026-04-15T03:03:17Z
- **Completed:** 2026-04-15T03:11:07Z
- **Tasks:** 2
- **Files modified:** 1

## Accomplishments
- 6 integration tests: format detection (Component), loading via ComponentBackend, 1 allow verdict, 3 deny verdicts
- Validates full TS SDK round trip: WIT types -> TS guard -> jco componentize -> host auto-detection -> correct evaluation
- Documented and tested the 11 MiB module-size issue: create_backend() rejects with default 10 MiB limit, ComponentBackend::with_limits() works
- Workspace verification: all tests pass, clippy clean on arc-wasm-guards, no regressions

## Task Commits

Each task was committed atomically:

1. **Task 1: Write Rust integration test for TypeScript-compiled guard** - `2b0694f` (test)
2. **Task 2: Full workspace verification** - No code changes; verification only

## Files Created/Modified
- `crates/arc-wasm-guards/tests/ts_guard_integration.rs` - 6 integration tests for TS-compiled guard in host runtime

## Decisions Made
- **Raised module-size limit to 15 MiB**: The jco componentize output embeds SpiderMonkey, producing ~11 MiB binaries. The default 10 MiB `max_module_size` on `ComponentBackend` rejects these. Tests use `with_limits(16 MiB memory, 15 MiB module)` directly instead of `create_backend()`.
- **1 billion fuel limit**: SpiderMonkey-based components consume significantly more fuel than native Rust guards. 1M fuel is insufficient; 1B fuel allows the JS runtime to initialize and evaluate.
- **Explicit rejection test**: `ts_guard_loads_via_create_backend` first verifies that `create_backend()` rejects the oversized module, then loads via `ComponentBackend` with raised limits. This documents the expected behavior for future SDK users.

## Deviations from Plan

None -- plan executed exactly as written. The plan anticipated the 11 MiB module-size issue and provided the `with_limits()` fallback path.

## Issues Encountered
- **Pre-existing clippy error in arc-http-core**: `too_many_arguments` on a function in `arc-http-core`. Not caused by this plan's changes; out of scope.
- **Pre-existing fmt issue**: Minor formatting difference in an existing example guard file. Not caused by this plan's changes; out of scope.

## User Setup Required
None -- no external service configuration required.

## Next Phase Readiness
- Phase 387 (TypeScript Guard SDK) is now fully complete: SDK scaffold, build pipeline, and host integration tests all verified
- The 11 MiB module-size pattern is documented for any future JS/TS guard compilation
- Future work: consider raising `create_backend()` default module limit or making it configurable for Component Model binaries

---
*Phase: 387-typescript-guard-sdk*
*Completed: 2026-04-14*
