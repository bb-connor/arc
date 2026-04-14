---
phase: 373-wasm-runtime-host-foundation
plan: 01
subsystem: wasm-runtime
tags: [wasmtime, wasm, host-functions, arc-engine, store-limits, tracing]

# Dependency graph
requires:
  - phase: 347-wasm-guard-skeleton
    provides: WasmtimeBackend skeleton with Store<()> and per-backend Engine
provides:
  - WasmHostState struct with config HashMap and bounded log buffer
  - Shared Arc<Engine> constructor (create_shared_engine)
  - Three registered host functions: arc.log, arc.get_config, arc.get_time_unix_secs
  - register_host_functions(Linker) for Linker-based host function setup
  - HostFunction error variant in WasmGuardError
  - WasmtimeBackend with_engine() and with_engine_and_config() constructors
affects: [373-02, 374-wasm-security-enrichment, 375-wasm-manifest-wiring]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Per-invocation Store<WasmHostState> with fresh state each evaluate() call"
    - "Host function registration via Linker::func_wrap with typed Caller closures"
    - "Bounded log buffer with MAX_LOG_ENTRIES=256 and silent drop on overflow"
    - "Shared Arc<Engine> across multiple WasmtimeBackend instances"
    - "StoreLimits activated via store.limiter() for memory bounds"
    - "WAT-based inline unit tests for host function verification"

key-files:
  created:
    - crates/arc-wasm-guards/src/host.rs
  modified:
    - crates/arc-wasm-guards/src/runtime.rs
    - crates/arc-wasm-guards/src/error.rs
    - crates/arc-wasm-guards/src/lib.rs

key-decisions:
  - "Store log level as i32 in buffer (ABI contract), map to tracing::Level only when emitting"
  - "Create fresh Linker per evaluate() call for simplicity over caching"
  - "Write partial data on arc.get_config truncation (POSIX read() semantics)"
  - "Silent drop on invalid log level or oversized message (no panics in host functions)"

patterns-established:
  - "WasmHostState pattern: per-invocation fresh state in Store for stateless guard execution"
  - "Host function safety: no panic, no unwrap, no expect; return sentinel values on error"
  - "WAT inline test modules: self-contained WASM test fixtures without external build toolchain"

requirements-completed: [WGRT-01, WGRT-02, WGRT-03, WGRT-04, WGRT-05]

# Metrics
duration: 20min
completed: 2026-04-14
---

# Phase 373 Plan 01: WASM Runtime Host Foundation Summary

**Shared Arc<Engine>, WasmHostState with bounded log buffer, and three host functions (arc.log, arc.get_config, arc.get_time_unix_secs) registered via wasmtime Linker**

## Performance

- **Duration:** 20 min
- **Started:** 2026-04-14T20:30:34Z
- **Completed:** 2026-04-14T20:50:56Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments
- Created WasmHostState struct with config HashMap, bounded log buffer (256 entries), and StoreLimits for memory bounds
- Implemented three host functions: arc.log (structured logging with tracing), arc.get_config (config lookup with truncation semantics), arc.get_time_unix_secs (wall-clock time)
- Refactored WasmtimeBackend from per-backend Engine to shared Arc<Engine> and from Store<()> to Store<WasmHostState>
- Added 9 WAT-based unit tests covering all host functions and edge cases (invalid level, oversized message, missing key, buffer bounding)
- All 24 crate tests pass, clippy clean, zero workspace regressions

## Task Commits

Each task was committed atomically:

1. **Task 1: Create WasmHostState, host function registration, and shared Engine constructor** - `ff91cba` (feat)
2. **Task 2: Refactor WasmtimeBackend to use Arc<Engine> and Store<WasmHostState>** - `5c96fb6` (feat)

## Files Created/Modified
- `crates/arc-wasm-guards/src/host.rs` - WasmHostState struct, create_shared_engine(), register_host_functions() with arc.log/get_config/get_time_unix_secs, 9 WAT-based tests
- `crates/arc-wasm-guards/src/runtime.rs` - Refactored WasmtimeBackend to use Arc<Engine>, Store<WasmHostState>, host function registration, log buffer drain
- `crates/arc-wasm-guards/src/error.rs` - Added HostFunction(String) error variant
- `crates/arc-wasm-guards/src/lib.rs` - Added pub mod host and pub use host::WasmHostState (feature-gated)

## Decisions Made
- Store log level as i32 in the buffer (matches the ABI contract); map to tracing::Level only when emitting via tracing macros
- Create a fresh Linker per evaluate() call rather than caching; func_wrap registrations are closure bindings not compilations, so overhead is minimal
- Write partial data on arc.get_config when output buffer is smaller than value (POSIX read() semantics); return actual length so guest detects truncation
- All host function closures silently return defaults on error (no panic, no unwrap, no expect); this is the fail-safe pattern for host-guest boundaries

## Deviations from Plan
None -- plan executed exactly as written.

## Issues Encountered
None.

## User Setup Required
None -- no external service configuration required.

## Next Phase Readiness
- Host function infrastructure is complete and ready for Plan 02 (arc_alloc and arc_deny_reason guest export detection)
- WasmHostState and register_host_functions are public APIs available for downstream phases
- StoreLimits is wired but the actual memory enforcement will be exercised more in Phase 374

---
*Phase: 373-wasm-runtime-host-foundation*
*Completed: 2026-04-14*
