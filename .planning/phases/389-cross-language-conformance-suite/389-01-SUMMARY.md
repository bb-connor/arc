---
phase: 389-cross-language-conformance-suite
plan: 01
subsystem: testing
tags: [wasm, conformance, yaml, wasmtime, component-model, cross-language]

# Dependency graph
requires:
  - phase: 383-guard-sdk-proc-macro
    provides: "arc-guard-sdk proc macro for Rust guard compilation"
  - phase: 387-ts-guard-sdk
    provides: "TypeScript guard SDK and compiled tool-gate.wasm"
  - phase: 388-multi-language-guard-sdks
    provides: "Python and Go guard SDKs with compiled tool-gate.wasm binaries"
provides:
  - "Shared YAML conformance fixture set (tool-gate + enriched-fields)"
  - "Cross-language conformance runner integration test"
  - "Per-guard per-fixture pass/fail reporting"
affects: [389-02, conformance-suite, guard-sdks]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Fresh backend per fixture for fuel state isolation"
    - "GuardEntry struct with wasm_bytes + make_backend factory fn for deferred loading"
    - "Graceful skip pattern via Option<GuardEntry> for missing guard binaries"

key-files:
  created:
    - "tests/conformance/fixtures/guard/tool-gate.yaml"
    - "tests/conformance/fixtures/guard/enriched-fields.yaml"
    - "crates/arc-wasm-guards/tests/conformance_runner.rs"
  modified: []

key-decisions:
  - "Fresh backend per fixture (not per guard) for fuel state isolation, enabling per-fixture fuel reporting in plan 02"
  - "GuardEntry carries wasm_bytes + factory fn rather than pre-loaded backend, avoiding fuel state leaking between fixtures"
  - "Rust guard panics if missing (mandatory); TS/Python/Go return None for graceful skip"

patterns-established:
  - "TestFixture YAML shape: name, request (GuardRequest), expected_verdict, deny_reason_contains"
  - "check_verdict() function for reusable verdict assertion across conformance tests"
  - "try_load_{lang}_guard() -> Option<GuardEntry> pattern for conditional guard loading"

requirements-completed: [CONF-01, CONF-02]

# Metrics
duration: 12min
completed: 2026-04-15
---

# Phase 389 Plan 01: Cross-Language Conformance Suite Summary

**Shared YAML conformance fixtures and integration runner proving Rust, TypeScript, and Python guards produce identical verdicts against 11 test cases**

## Performance

- **Duration:** 12 min
- **Started:** 2026-04-15T03:58:51Z
- **Completed:** 2026-04-15T04:11:20Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments
- 7 tool-gate YAML fixtures covering allow, deny with reason matching, scopes, and arguments
- 4 enriched-fields YAML fixtures covering action_type and extracted_path for the Rust enriched-inspector guard
- Conformance runner that loads all 4 language guards and runs each against every fixture with per-guard per-fixture reporting
- 21/21 tool-gate fixtures pass across Rust + TypeScript + Python (Go skipped, no TinyGo binary)
- 4/4 enriched-inspector fixtures pass for the Rust guard

## Task Commits

Each task was committed atomically:

1. **Task 1: Create shared YAML conformance fixture files** - `0a51ed1` (test)
2. **Task 2: Create conformance runner integration test** - `6994618` (test)

## Files Created/Modified
- `tests/conformance/fixtures/guard/tool-gate.yaml` - 7 fixtures for the tool-gate deny-list policy across all languages
- `tests/conformance/fixtures/guard/enriched-fields.yaml` - 4 fixtures for enriched field inspection (Rust only)
- `crates/arc-wasm-guards/tests/conformance_runner.rs` - Integration test running all guards against all fixtures

## Decisions Made
- Fresh backend per fixture (not per guard) for fuel state isolation. This is critical for plan 02 which adds per-fixture fuel reporting (CONF-03).
- GuardEntry struct carries raw wasm_bytes and a factory function rather than a pre-loaded backend, preventing fuel state from leaking between fixtures.
- Rust guard is mandatory (panics if not found); TS, Python, and Go guards are optional (return None for graceful skip with [SKIP] output).

## Deviations from Plan

None -- plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None -- no external service configuration required.

## Next Phase Readiness
- Conformance runner is ready for plan 02 to add fuel envelope collection, comparison matrix, and CI integration
- The fresh-backend-per-fixture pattern ensures accurate per-fixture fuel readings for CONF-03
- Go guard will automatically be included once TinyGo binary is available

---
*Phase: 389-cross-language-conformance-suite*
*Completed: 2026-04-15*
