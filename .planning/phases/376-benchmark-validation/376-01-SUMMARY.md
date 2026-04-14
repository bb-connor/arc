---
phase: 376-benchmark-validation
plan: 01
subsystem: testing
tags: [criterion, wasmtime, wasm, benchmarking, performance]

requires:
  - phase: 375-guard-manifest-and-wiring
    provides: WasmHostState, create_shared_engine, register_host_functions, WasmtimeBackend
provides:
  - Criterion benchmark harness for arc-wasm-guards
  - Module compilation benchmarks for 50 KiB and 5 MiB WAT modules
  - Instantiation overhead benchmark with iter_batched fresh Store pattern
  - WAT builder helpers (build_trivial_guard_wat, build_sized_wat) reusable by Plan 02
affects: [376-02, v4.0-guard-performance-validation]

tech-stack:
  added: [criterion (dev-dependency for arc-wasm-guards)]
  patterns: [feature-gated bench entry, file-level lint suppression for bench binaries, WAT data-segment sizing]

key-files:
  created:
    - crates/arc-wasm-guards/benches/wasm_guard_perf.rs
  modified:
    - crates/arc-wasm-guards/Cargo.toml

key-decisions:
  - "File-level #![allow(clippy::unwrap_used, clippy::expect_used)] for bench binary since cfg_attr(test) does not apply"
  - "WAT data segment padding with \\00 for approximate target binary sizes (within ~10%)"
  - "sample_size(10) for 5 MiB compilation benchmark to keep total bench time reasonable"

patterns-established:
  - "Feature-gated [[bench]] with required-features for wasmtime-runtime"
  - "WAT builder helpers for generating sized modules with arc.* imports"
  - "iter_batched with fresh Store+Linker per iteration for instantiation benchmarks"

requirements-completed: [WGBENCH-01, WGBENCH-02]

duration: 6min
completed: 2026-04-14
---

# Phase 376 Plan 01: Benchmark Harness and Compilation/Instantiation Benchmarks Summary

**Criterion benchmark harness for WASM guard compilation (50 KiB + 5 MiB) and per-call instantiation overhead using WAT data-segment sizing**

## Performance

- **Duration:** 6 min
- **Started:** 2026-04-14T22:51:32Z
- **Completed:** 2026-04-14T22:57:39Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- Criterion dev-dependency and feature-gated [[bench]] entry added to arc-wasm-guards Cargo.toml
- Compilation benchmark group measuring Module::new() for ~50 KiB and ~5 MiB WAT modules
- Instantiation benchmark using iter_batched with fresh Store/Linker per iteration (matches production evaluate() path)
- All 83 existing crate tests pass, clippy clean, bench dry-run succeeds

## Task Commits

Each task was committed atomically:

1. **Task 1: Add Criterion dev-dependency and bench entry** - `6324ebe` (chore)
2. **Task 2: Create wasm_guard_perf.rs with compilation and instantiation benchmarks** - `91534aa` (feat)

## Files Created/Modified
- `crates/arc-wasm-guards/Cargo.toml` - Added criterion dev-dep, [[bench]] entry with required-features
- `crates/arc-wasm-guards/benches/wasm_guard_perf.rs` - Criterion benchmark file with compilation + instantiation groups (152 lines)

## Decisions Made
- Used file-level `#![allow(clippy::unwrap_used, clippy::expect_used)]` because benchmark binaries are not compiled under `#[cfg(test)]`, so the crate's `cfg_attr(test, ...)` does not apply
- WAT data segments with `\00` padding for approximate binary size targets (within ~10% accuracy is acceptable per the decision doc)
- Reduced sample_size to 10 for the 5 MiB compilation benchmark to keep total bench runtime manageable

## Deviations from Plan

None -- plan executed exactly as written.

## Issues Encountered
None

## User Setup Required
None -- no external service configuration required.

## Next Phase Readiness
- Benchmark harness is ready for Plan 02 to add evaluate latency, fuel overhead, and ResourceLimiter benchmarks
- WAT builder helpers (build_trivial_guard_wat, build_sized_wat) are available for reuse
- criterion_group! macro can be extended with additional benchmark functions

---
*Phase: 376-benchmark-validation*
*Completed: 2026-04-14*
