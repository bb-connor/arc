---
phase: 374-security-hardening-and-request-enrichment
plan: 01
subsystem: security
tags: [wasm, wasmtime, resource-limits, import-validation, fail-closed]

requires:
  - phase: 373-wasm-runtime-host-foundation
    provides: WasmHostState, shared Arc<Engine>, host functions, WasmtimeBackend

provides:
  - ImportViolation and ModuleTooLarge error variants
  - Configurable max_memory_bytes and max_module_size on WasmGuardConfig
  - WasmHostState::with_memory_limit() with trap_on_grow_failure(true)
  - Module size validation before compilation in load_module
  - Import namespace validation rejecting non-arc imports in load_module
  - Configurable memory limit enforcement in evaluate via ResourceLimiter

affects: [374-02, wasm-guards, guard-sdk]

tech-stack:
  added: []
  patterns: [trap-on-grow-failure for fail-closed memory enforcement, import namespace allowlisting, pre-compilation size gating]

key-files:
  created: []
  modified:
    - crates/arc-wasm-guards/src/error.rs
    - crates/arc-wasm-guards/src/config.rs
    - crates/arc-wasm-guards/src/host.rs
    - crates/arc-wasm-guards/src/runtime.rs

key-decisions:
  - "trap_on_grow_failure(true) chosen over returning -1 from memory.grow to ensure fail-closed behavior (WGSEC-01)"
  - "Import validation placed after Module::new() so wasmtime handles binary parsing, then we check the import table"
  - "Module size check placed before Module::new() to avoid unnecessary compilation of oversized modules"

patterns-established:
  - "with_limits() builder pattern on WasmtimeBackend for test-friendly resource limit configuration"
  - "Pre-compilation size gating: reject before expensive compilation"
  - "Post-compilation import validation: leverage wasmtime's import introspection API"

requirements-completed: [WGSEC-01, WGSEC-02, WGSEC-03]

duration: 6min
completed: 2026-04-14
---

# Phase 374 Plan 01: WASM Guard Security Hardening Summary

**ResourceLimiter memory caps with trap-on-grow, import namespace validation rejecting non-arc modules, and module size gating before compilation**

## Performance

- **Duration:** 6 min
- **Started:** 2026-04-14T21:26:46Z
- **Completed:** 2026-04-14T21:33:36Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments
- Three fail-closed security enforcement mechanisms for untrusted WASM guard modules
- ImportViolation and ModuleTooLarge error variants with clear diagnostic messages
- Configurable max_memory_bytes (16 MiB default) and max_module_size (10 MiB default) on WasmGuardConfig
- WasmHostState::with_memory_limit() with trap_on_grow_failure(true) ensuring memory growth beyond cap traps instead of silently failing
- Import namespace validation in load_module rejecting any import not from the "arc" namespace
- Module size validation before compilation in both WasmtimeBackend::load_module and WasmGuardRuntime::load_guard
- 11 new tests (5 unit tests for types/config, 6 WAT-based integration tests for security enforcement)
- All 44 crate tests pass, clippy clean

## Task Commits

Each task was committed atomically:

1. **Task 1: Add security error variants and configurable limits** - `7da6858` (feat)
2. **Task 2: Enforce security checks in WasmtimeBackend** - `f4909ae` (feat)

## Files Created/Modified
- `crates/arc-wasm-guards/src/error.rs` - Added ImportViolation and ModuleTooLarge error variants
- `crates/arc-wasm-guards/src/config.rs` - Added max_memory_bytes and max_module_size fields with serde defaults
- `crates/arc-wasm-guards/src/host.rs` - Added with_memory_limit() constructor with trap_on_grow_failure(true)
- `crates/arc-wasm-guards/src/runtime.rs` - Added module size check, import validation, configurable memory limit, with_limits() builder, and 6 WAT-based tests

## Decisions Made
- Used trap_on_grow_failure(true) so memory.grow beyond the configured cap causes a trap (fail-closed) rather than returning -1 (which would silently succeed with -1 as the memory.grow result)
- Import validation is placed after Module::new() to leverage wasmtime's import table parsing, while module size validation is placed before to avoid unnecessary compilation
- Added with_limits() builder method on WasmtimeBackend for ergonomic test configuration without changing defaults

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- Security hardening complete; WGSEC-01, WGSEC-02, WGSEC-03 all enforced and tested
- Plan 374-02 (request enrichment) can proceed, building on these configurable limits

---
*Phase: 374-security-hardening-and-request-enrichment*
*Completed: 2026-04-14*
