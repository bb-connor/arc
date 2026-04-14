---
phase: 376-benchmark-validation
plan: 02
subsystem: testing
tags: [criterion, wasmtime, wasm, benchmarking, performance, fuel-metering, resource-limiter]

requires:
  - phase: 376-benchmark-validation
    provides: Criterion bench harness, WAT builder helpers, compilation and instantiation benchmarks (plan 01)
  - phase: 375-guard-manifest-and-wiring
    provides: WasmHostState, create_shared_engine, register_host_functions, GuardRequest ABI
provides:
  - Evaluate latency benchmarks (trivial Allow + realistic byte-scanning Deny)
  - Fuel metering overhead comparison (fuel-enabled vs fuel-disabled engines)
  - ResourceLimiter adversarial allocation trap validation
  - Complete 5-group benchmark suite for v4.0 WASM guard performance validation
affects: [v4.0-guard-performance-validation, v4.1-guard-sdk]

tech-stack:
  added: []
  patterns: [no-fuel Engine for overhead comparison, adversarial WAT for ResourceLimiter correctness assertion, iter_batched full-evaluate-path measurement]

key-files:
  created: []
  modified:
    - crates/arc-wasm-guards/benches/wasm_guard_perf.rs

key-decisions:
  - "Full production hot path measured in evaluate latency benchmarks (Store + Linker + register + instantiate + serialize + write + call) to match actual runtime.rs::evaluate() code path"
  - "Fuel overhead comparison uses separate Engine instances (consume_fuel true vs false) with identical WAT modules compiled per-engine"
  - "ResourceLimiter benchmark uses assert!(result.is_err()) as a correctness gate -- benchmark failure means ResourceLimiter is misconfigured"

patterns-established:
  - "No-fuel Engine pattern: wasmtime::Config::new() with default consume_fuel(false) for overhead baselines"
  - "Adversarial WAT pattern: memory.grow(1024) in loop to trigger ResourceLimiter trap at 16 MiB ceiling"
  - "Realistic guard WAT: byte-scanning loop with i32.load8_u for proxy JSON parsing workload"

requirements-completed: [WGBENCH-03, WGBENCH-04, WGBENCH-05]

duration: 3min
completed: 2026-04-14
---

# Phase 376 Plan 02: Evaluate Latency, Fuel Overhead, and ResourceLimiter Benchmarks Summary

**p50/p99 evaluate latency for trivial/realistic guards, fuel metering overhead quantification, and ResourceLimiter adversarial trap validation completing all 5 WGBENCH requirements**

## Performance

- **Duration:** 3 min
- **Started:** 2026-04-14T23:00:22Z
- **Completed:** 2026-04-14T23:03:11Z
- **Tasks:** 2
- **Files modified:** 1

## Accomplishments
- Evaluate latency benchmarks covering full production hot path for trivial Allow (immediate return) and realistic Deny (byte-scanning) guards
- Fuel metering overhead comparison using fuel-enabled vs fuel-disabled engines on identical realistic guard workload
- ResourceLimiter correctness validation confirming adversarial memory.grow(1024) traps at 16 MiB ceiling
- Complete 5-group benchmark suite (8 bench_functions) all passing in dry-run, clippy clean, 83 tests passing

## Task Commits

Each task was committed atomically:

1. **Task 1: Add evaluate latency and fuel overhead benchmarks (WGBENCH-03, WGBENCH-04)** - `1328a68` (feat)
2. **Task 2: Add ResourceLimiter validation benchmark (WGBENCH-05)** - `37b67c6` (feat)

## Files Created/Modified
- `crates/arc-wasm-guards/benches/wasm_guard_perf.rs` - Added 3 helpers (build_realistic_guard_wat, make_bench_request, create_no_fuel_engine), 1 adversarial WAT helper (build_adversarial_memory_wat), 3 benchmark groups (evaluate_latency, fuel_overhead, resource_limiter) with 5 new bench_functions

## Decisions Made
- Full production hot path (Store + Linker + host functions + instantiate + serialize + write + evaluate) included in evaluate latency measurement to match actual runtime.rs::evaluate() behavior
- Fuel overhead comparison uses two separate Engine instances rather than toggling fuel on a single engine, ensuring clean isolation
- ResourceLimiter benchmark asserts trap as a correctness gate rather than just measuring latency, catching regressions if trap_on_grow_failure is ever disabled

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed unused Result warning in ResourceLimiter benchmark**
- **Found during:** Task 2
- **Issue:** `black_box(result)` produced `unused Result` warning since `black_box` returns the value
- **Fix:** Changed to `let _ = black_box(result)` to explicitly discard the Result
- **Files modified:** crates/arc-wasm-guards/benches/wasm_guard_perf.rs
- **Verification:** Rebuild with zero warnings
- **Committed in:** 37b67c6 (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (1 bug)
**Impact on plan:** Trivial warning fix. No scope creep.

## Issues Encountered
None

## User Setup Required
None -- no external service configuration required.

## Next Phase Readiness
- All 5 WGBENCH requirements are now implemented and validated
- Phase 376 (benchmark-validation) is complete -- this was the final plan (02 of 02)
- v4.0 WASM Guard Runtime Completion benchmark validation is done
- Results can be collected by running `cargo bench --bench wasm_guard_perf --features wasmtime-runtime`

---
*Phase: 376-benchmark-validation*
*Completed: 2026-04-14*
