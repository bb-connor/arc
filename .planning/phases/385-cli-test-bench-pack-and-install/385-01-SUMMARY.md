---
phase: 385-cli-test-bench-pack-and-install
plan: 01
subsystem: cli
tags: [wasm, guard, cli, yaml, benchmark, wasmtime]

# Dependency graph
requires:
  - phase: 384-guard-cli-scaffold
    provides: "guard.rs module with cmd_guard_new, cmd_guard_build, cmd_guard_inspect"
  - phase: 373-wasm-guard-runtime
    provides: "WasmtimeBackend, GuardRequest, GuardVerdict, WasmGuardAbi trait"
provides:
  - "arc guard test: YAML fixture-based testing of compiled .wasm guards"
  - "arc guard bench: latency and fuel benchmarking with p50/p99 reporting"
  - "TestFixture YAML format for guard authors"
  - "Test/Bench/Pack/Install GuardCommands enum variants (Pack/Install are stubs for Plan 02)"
affects: [385-02, guard-sdk-docs]

# Tech tracking
tech-stack:
  added: [serde_yml for fixture YAML parsing]
  patterns: [fresh WasmtimeBackend per evaluation for fuel/memory isolation, YAML fixture-driven guard testing]

key-files:
  created: []
  modified:
    - crates/arc-cli/src/guard.rs
    - crates/arc-cli/src/cli/types.rs
    - crates/arc-cli/src/cli/dispatch.rs
    - crates/arc-cli/Cargo.toml

key-decisions:
  - "Fresh WasmtimeBackend per fixture/iteration instead of reusing backend, to ensure fuel and memory state isolation"
  - "TestFixture YAML format uses flat list of fixtures per file with GuardRequest shape for the request field"
  - "Percentile uses index = len * pct / 100 clamped to len-1 for simplicity"

patterns-established:
  - "YAML fixture testing: each fixture has name, request (GuardRequest shape), expected_verdict (allow/deny), optional deny_reason_contains"
  - "Bench warmup pattern: 5 warmup iterations before measured iterations"
  - "Per-fixture fresh backend: create WasmtimeBackend + load_module for each evaluation to avoid stale state"

requirements-completed: [GCLI-04, GCLI-05, GCLI-06]

# Metrics
duration: 17min
completed: 2026-04-15
---

# Phase 385 Plan 01: CLI Test and Bench Summary

**arc guard test with YAML fixture-driven pass/fail reporting and arc guard bench with p50/p99 latency and fuel statistics**

## Performance

- **Duration:** 17 min
- **Started:** 2026-04-15T01:10:40Z
- **Completed:** 2026-04-15T01:27:40Z
- **Tasks:** 3 (Task 1 pre-completed)
- **Files modified:** 5

## Accomplishments
- arc guard test loads .wasm guards and runs YAML fixture files with per-fixture pass/fail verdict matching, deny reason substring checking, and summary counts
- arc guard bench loads .wasm guards and runs N iterations with warmup phase, reporting p50/p99/min/max/mean for both latency and fuel consumption
- TestFixture YAML format supports all GuardRequest fields including optional action_type, extracted_path, extracted_target, filesystem_roots, and matched_grant_index
- 20 unit tests passing: fixture YAML deserialization, verdict checking, percentile computation, formatting helpers

## Task Commits

Each task was committed atomically:

1. **Task 1: Add arc-wasm-guards dependency and Test/Bench enum variants** - `1e4baec` (feat)
2. **Task 2: Implement arc guard test with YAML fixture format** - `381ca94` (feat)
3. **Task 3: Implement arc guard bench with p50/p99 reporting** - `8ad8b84` (feat)

## Files Created/Modified
- `crates/arc-cli/src/guard.rs` - TestFixture struct, cmd_guard_test, cmd_guard_bench, percentile/mean/format helpers, 13 new unit tests
- `crates/arc-cli/src/cli/types.rs` - Test, Bench, Pack, Install variants in GuardCommands enum
- `crates/arc-cli/src/cli/dispatch.rs` - Dispatch arms routing new commands to guard.rs functions
- `crates/arc-cli/Cargo.toml` - arc-wasm-guards dependency with wasmtime-runtime feature
- `crates/arc-http-core/src/authority.rs` - Manual Debug impl to fix pre-existing compilation error

## Decisions Made
- Fresh WasmtimeBackend per fixture/iteration: the wasmtime Store carries per-evaluation state (fuel counter, linear memory), so reusing would corrupt fuel measurements and state isolation
- TestFixture uses the exact GuardRequest serde shape for the request field, meaning YAML fixtures naturally mirror the runtime request format
- Percentile calculation uses integer-based index computation (len * pct / 100) clamped to len-1, matching common non-interpolating percentile semantics
- format_number uses manual comma insertion for u64 display without external dependencies

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed pre-existing Debug derive error in arc-http-core**
- **Found during:** Task 2 (compilation attempt)
- **Issue:** HttpAuthority derived Debug but Keypair (ed25519 SigningKey) does not implement Debug, causing compilation failure across the dependency chain
- **Fix:** Replaced derive(Debug) with manual Debug impl that omits the keypair field
- **Files modified:** crates/arc-http-core/src/authority.rs
- **Verification:** cargo check -p arc-cli passes
- **Committed in:** 381ca94 (Task 2 commit)

**2. [Rule 3 - Blocking] Fixed pre-existing duplicate re-export in arc-core-types**
- **Found during:** Task 2 (test compilation attempt)
- **Issue:** sha256_hex was re-exported from both crypto and hashing modules, causing E0252 duplicate definition error in test profile
- **Fix:** Removed duplicate re-export from hashing module (crypto re-export is canonical)
- **Files modified:** crates/arc-core-types/src/lib.rs
- **Verification:** cargo test -p arc-cli passes
- **Committed in:** 381ca94 (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (2 blocking pre-existing compilation errors)
**Impact on plan:** Both fixes required for compilation. No scope creep.

## Issues Encountered
None beyond the pre-existing compilation errors documented above.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- guard.rs has cmd_guard_pack() and cmd_guard_install() stubs ready for Plan 02 implementation
- GuardCommands::Pack and Install enum variants and dispatch arms already wired
- All existing tests (20) passing, clippy clean, fmt clean

---
*Phase: 385-cli-test-bench-pack-and-install*
*Completed: 2026-04-15*
