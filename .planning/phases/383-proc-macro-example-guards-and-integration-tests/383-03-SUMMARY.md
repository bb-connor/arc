---
phase: 383-proc-macro-example-guards-and-integration-tests
plan: 03
subsystem: testing
tags: [wasm, guard-sdk, integration-tests, wasmtime, proc-macro]

requires:
  - phase: 383-02
    provides: "tool-gate and enriched-inspector example guard WASM binaries"
  - phase: 383-01
    provides: "#[arc_guard] proc-macro attribute for ABI generation"
  - phase: 373
    provides: "WasmtimeBackend with host function support"
provides:
  - "Integration test suite proving full SDK-to-host round trip for WASM guards"
  - "9 tests covering allow, deny, deny-reason, enriched fields, and host config scenarios"
affects: [arc guard new scaffold, SDK documentation, future guard authoring]

tech-stack:
  added: []
  patterns: [integration test loading compiled WASM binaries via WasmtimeBackend, cfg-gated test files behind wasmtime-runtime feature]

key-files:
  created:
    - crates/arc-wasm-guards/tests/example_guard_integration.rs
  modified: []

key-decisions:
  - "Each test creates a fresh WasmtimeBackend instance with a shared engine via create_shared_engine() for isolation"
  - "Helper functions (load_example_wasm, make_request, make_enriched_request) factor out repeated setup to keep tests concise"
  - "WASM binary path uses env!(CARGO_MANIFEST_DIR)/../../target/ for reliable path resolution from any cargo invocation context"

patterns-established:
  - "Integration test pattern for WASM guards: load_example_wasm(artifact_name) -> WasmtimeBackend::with_engine -> load_module -> evaluate -> assert verdict"
  - "Deny reason verification pattern: match on GuardVerdict::Deny { reason: Some(r) } with substring assertion"

requirements-completed: [GEXM-05]

duration: 3min
completed: 2026-04-14
---

# Phase 383 Plan 03: Integration Tests for SDK-compiled Example Guards Summary

**9 integration tests loading tool-gate and enriched-inspector WASM binaries into WasmtimeBackend, proving the full #[arc_guard] proc macro to host evaluation round trip**

## Performance

- **Duration:** 3 min
- **Started:** 2026-04-14T23:59:15Z
- **Completed:** 2026-04-15T00:02:30Z
- **Tasks:** 1
- **Files modified:** 1 (1 created)

## Accomplishments
- Created integration test suite with 9 tests covering both example guards end-to-end
- Verified tool-gate guard allows safe tools and denies dangerous_tool, rm_rf, drop_database with correct deny reasons
- Verified enriched-inspector guard reads action_type/extracted_path fields and blocks writes to /etc
- Verified host config injection via with_engine_and_config for configurable blocked path protection
- Proved complete SDK round trip: #[arc_guard] proc macro -> WASM compilation -> host loading -> evaluation -> verdict

## Task Commits

Each task was committed atomically:

1. **Task 1: Write integration tests loading example guard .wasm into WasmtimeBackend** - `fdaa3e1` (test)

## Files Created/Modified
- `crates/arc-wasm-guards/tests/example_guard_integration.rs` - Integration tests for SDK-compiled example guards loading .wasm into WasmtimeBackend

## Decisions Made
- Each test creates its own WasmtimeBackend for clean isolation (Module loaded once, Store created per-evaluate)
- Helper functions extract common setup to keep individual test bodies readable and focused on assertions
- WASM path resolution uses CARGO_MANIFEST_DIR for reliable cross-context path computation

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Phase 383 (proc-macro, example guards, and integration tests) is fully complete
- All GEXM requirements (01-05) satisfied across plans 01, 02, and 03
- The test suite validates the guard authoring pipeline end-to-end, providing a regression safety net for future SDK changes
- Example guards and tests serve as templates for the future `arc guard new` scaffold

## Self-Check: PASSED

---
*Phase: 383-proc-macro-example-guards-and-integration-tests*
*Completed: 2026-04-14*
