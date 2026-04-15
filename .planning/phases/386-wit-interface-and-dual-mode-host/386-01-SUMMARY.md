---
phase: 386-wit-interface-and-dual-mode-host
plan: 01
subsystem: wasm-guards
tags: [wit, wasmtime, component-model, bindgen, wasm]

requires:
  - phase: 373-wasm-guard-runtime
    provides: "WasmGuardAbi trait, WasmtimeBackend, host.rs Engine config"
  - phase: 374-host-validation-and-enrichment
    provides: "GuardRequest enrichment fields, import validation pattern"
provides:
  - "WIT package arc:guard@0.1.0 at wit/arc-guard/world.wit"
  - "ComponentBackend implementing WasmGuardAbi via bindgen!-generated types"
  - "Shared Engine with Component Model support (wasm_component_model(true))"
  - "wasmparser 0.221 dependency gated on wasmtime-runtime feature"
affects: [386-02, dual-mode-dispatch, guard-format-detection]

tech-stack:
  added: [wasmparser-0.221, wasmtime-component-model]
  patterns: [wit-bindgen-codegen, component-store-state-wrapper, type-conversion-helpers]

key-files:
  created:
    - wit/arc-guard/world.wit
    - crates/arc-wasm-guards/src/component.rs
  modified:
    - crates/arc-wasm-guards/src/host.rs
    - crates/arc-wasm-guards/src/lib.rs
    - crates/arc-wasm-guards/Cargo.toml

key-decisions:
  - "WIT types placed inside an interface block (not top-level) because the WIT parser requires variant/record inside interface or world scope"
  - "ComponentState(StoreLimits) wrapper used for Store data instead of WasmHostState because component guards have no host imports"
  - "Guard::instantiate returns Guard directly (not tuple) in wasmtime 29 -- adapted from plan's tuple destructuring"

patterns-established:
  - "WIT interface + world pattern: types in interface block, re-used in world via use statement"
  - "ComponentState wrapper: lightweight Store data for import-free component evaluation"
  - "Type conversion helpers: to_wit_request() and from_wit_verdict() isolate WIT boundary mapping"

requirements-completed: [WIT-01, WIT-02, WIT-04]

duration: 6min
completed: 2026-04-15
---

# Phase 386 Plan 01: WIT Interface and Component Backend Summary

**WIT package arc:guard@0.1.0 with bindgen!-generated ComponentBackend and Component Model-enabled shared Engine**

## Performance

- **Duration:** 6 min
- **Started:** 2026-04-15T02:28:21Z
- **Completed:** 2026-04-15T02:34:00Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments
- Created WIT package at wit/arc-guard/world.wit defining the arc:guard@0.1.0 contract with verdict variant, guard-request record (all 10 fields), and guard world
- Built ComponentBackend that implements WasmGuardAbi using wasmtime::component::bindgen!-generated types -- no manual ABI glue
- Enabled Component Model on the shared Engine so both core modules and Component Model guards work on the same Engine
- Added wasmparser 0.221 as optional dependency for format detection in Plan 02

## Task Commits

Each task was committed atomically:

1. **Task 1: Create WIT package and add wasmparser dependency** - `2b0bc7f` (feat)
2. **Task 2: Create ComponentBackend with bindgen! and update Engine config** - `e8f4c1c` (feat)

## Files Created/Modified
- `wit/arc-guard/world.wit` - WIT package defining arc:guard@0.1.0 with types interface, guard-request record, verdict variant, and guard world
- `crates/arc-wasm-guards/src/component.rs` - ComponentBackend with bindgen! macro, type conversion helpers, StoreLimits enforcement
- `crates/arc-wasm-guards/src/host.rs` - Added config.wasm_component_model(true) to create_shared_engine()
- `crates/arc-wasm-guards/src/lib.rs` - Registered component module and re-exported ComponentBackend
- `crates/arc-wasm-guards/Cargo.toml` - Added wasmparser 0.221 optional dependency, updated wasmtime-runtime feature

## Decisions Made
- WIT types placed inside an `interface types` block rather than at the top-level of the file because the WIT parser requires variant and record definitions to live inside an interface or world scope; the world then uses `use types.{verdict, guard-request}` to import them
- `Guard::instantiate` in wasmtime 29 returns `Guard` directly (not a tuple like earlier versions), so the plan's `(bindings, _instance)` destructure was adapted to a plain `let bindings =` binding
- `ComponentState(StoreLimits)` wrapper struct used for Store data instead of reusing `WasmHostState`, because the guard world has no imports and does not need config or log buffers

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] WIT types must be inside interface block**
- **Found during:** Task 1 (WIT file creation) / Task 2 (compilation)
- **Issue:** The plan's WIT definition placed `variant verdict` and `record guard-request` at the package top level, but the WIT parser expects these inside an `interface` or `world` block
- **Fix:** Wrapped types in an `interface types { ... }` block and added `use types.{verdict, guard-request}` in the world definition
- **Files modified:** wit/arc-guard/world.wit
- **Verification:** cargo check -p arc-wasm-guards --features wasmtime-runtime succeeds
- **Committed in:** e8f4c1c (Task 2 commit, since the WIT file was already committed in Task 1 and the fix was part of getting component.rs to compile)

**2. [Rule 3 - Blocking] Guard::instantiate return type differs in wasmtime 29**
- **Found during:** Task 2 (ComponentBackend implementation)
- **Issue:** Plan specified `let (bindings, _instance) = Guard::instantiate(...)` but wasmtime 29 returns `Guard` directly, not a tuple
- **Fix:** Changed to `let bindings = Guard::instantiate(...)` with explicit error type annotation
- **Files modified:** crates/arc-wasm-guards/src/component.rs
- **Verification:** cargo check succeeds
- **Committed in:** e8f4c1c (Task 2 commit)

**3. [Rule 3 - Blocking] Removed duplicate cfg attribute flagged by clippy**
- **Found during:** Task 2 (clippy verification)
- **Issue:** `#![cfg(feature = "wasmtime-runtime")]` inside component.rs duplicated the `#[cfg(feature = "wasmtime-runtime")]` already on the module declaration in lib.rs
- **Fix:** Removed the inner `#![cfg(...)]` attribute from component.rs
- **Files modified:** crates/arc-wasm-guards/src/component.rs
- **Verification:** cargo clippy -D warnings passes clean
- **Committed in:** e8f4c1c (Task 2 commit)

---

**Total deviations:** 3 auto-fixed (3 blocking issues)
**Impact on plan:** All auto-fixes necessary for compilation and clippy compliance. No scope creep.

## Issues Encountered
None beyond the deviations noted above.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- WIT package and ComponentBackend are ready for Plan 02 (dual-mode dispatch with wasmparser format detection)
- wasmparser dependency available for distinguishing core modules from Component Model components
- All 83 existing unit tests + 9 integration tests continue to pass

---
*Phase: 386-wit-interface-and-dual-mode-host*
*Completed: 2026-04-15*
