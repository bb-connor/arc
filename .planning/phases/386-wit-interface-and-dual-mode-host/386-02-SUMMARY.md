---
phase: 386-wit-interface-and-dual-mode-host
plan: 02
subsystem: wasm-guards
tags: [wasm, wasmparser, component-model, dual-mode, format-detection]

requires:
  - phase: 386-01
    provides: "ComponentBackend, WIT package arc:guard@0.1.0, wasmparser 0.221 dependency"
  - phase: 373-wasm-guard-runtime
    provides: "WasmtimeBackend, WasmGuardAbi trait, host.rs shared Engine"
provides:
  - "WasmFormat enum for binary format classification (CoreModule vs Component)"
  - "detect_wasm_format() function using wasmparser for authoritative format detection"
  - "create_backend() factory that auto-routes to WasmtimeBackend or ComponentBackend"
  - "WasmGuardError::UnrecognizedFormat variant for invalid binaries"
  - "Complete dual-mode public API: WasmFormat, detect_wasm_format, create_backend, ComponentBackend"
affects: [guard-loading, wiring, dual-mode-evaluation]

tech-stack:
  added: []
  patterns: [wasmparser-format-detection, dual-mode-backend-factory, magic-byte-routing]

key-files:
  created: []
  modified:
    - crates/arc-wasm-guards/src/runtime.rs
    - crates/arc-wasm-guards/src/error.rs
    - crates/arc-wasm-guards/src/lib.rs

key-decisions:
  - "wasmparser::Parser::is_component() and is_core_wasm() used as authoritative format detectors (not manual magic byte comparison)"
  - "create_backend() returns Box<dyn WasmGuardAbi> for polymorphic dispatch without callers needing to know the format"
  - "WasmFormat enum, detect_wasm_format, and create_backend placed inside wasmtime_backend module (feature-gated) since they depend on wasmparser and wasmtime"

patterns-established:
  - "Format detection pattern: wasmparser::Parser static methods for binary classification at load time"
  - "Backend factory pattern: create_backend() encapsulates format detection + backend creation + module loading in one call"
  - "Dual-mode re-export pattern: runtime::wasmtime_backend items re-exported from lib.rs under wasmtime-runtime feature gate"

requirements-completed: [WIT-03]

duration: 6min
completed: 2026-04-15
---

# Phase 386 Plan 02: Dual-Mode WASM Format Detection and Routing Summary

**Automatic core-module vs component-model detection using wasmparser with factory-based backend dispatch**

## Performance

- **Duration:** 6 min
- **Started:** 2026-04-15T02:36:32Z
- **Completed:** 2026-04-15T02:42:21Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments
- Added WasmFormat enum and detect_wasm_format() function that uses wasmparser::Parser for authoritative binary format detection
- Added create_backend() factory that inspects WASM bytes and routes to WasmtimeBackend (core modules) or ComponentBackend (components) transparently
- Added WasmGuardError::UnrecognizedFormat variant for binaries that are neither core modules nor components
- Updated crate documentation to describe dual-mode support and re-exported all new public types from lib.rs
- All 86 unit tests + 9 integration tests pass, clippy clean

## Task Commits

Each task was committed atomically:

1. **Task 1: Add WasmFormat enum, detection, and create_backend factory** - `c86ae79` (feat)
2. **Task 2: Wire module exports and run full workspace checks** - `39bb4e9` (feat)

## Files Created/Modified
- `crates/arc-wasm-guards/src/error.rs` - Added UnrecognizedFormat variant to WasmGuardError
- `crates/arc-wasm-guards/src/runtime.rs` - Added WasmFormat enum, detect_wasm_format(), create_backend(), and 3 unit tests inside wasmtime_backend module
- `crates/arc-wasm-guards/src/lib.rs` - Re-exported WasmFormat, create_backend, detect_wasm_format; updated crate doc comment for dual-mode

## Decisions Made
- Used wasmparser::Parser::is_component() and is_core_wasm() as the authoritative format detectors rather than manual magic byte comparison, since wasmparser is already a dependency and these methods handle all edge cases
- create_backend() returns Box<dyn WasmGuardAbi> so callers get polymorphic dispatch without needing to know the binary format
- All new items placed inside the wasmtime_backend module (feature-gated) since they depend on wasmparser and wasmtime Engine types

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Dual-mode public API is complete: WasmFormat, detect_wasm_format, create_backend, ComponentBackend
- Guard loading code (wiring.rs) can now use create_backend() to transparently support both core-module and Component Model guards
- All existing core-module guards continue working unchanged (backward compatible)

---
*Phase: 386-wit-interface-and-dual-mode-host*
*Completed: 2026-04-15*
