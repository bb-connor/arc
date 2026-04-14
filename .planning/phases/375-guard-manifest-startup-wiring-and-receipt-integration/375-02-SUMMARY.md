---
phase: 375-guard-manifest-startup-wiring-and-receipt-integration
plan: 02
subsystem: wasm-guards
tags: [wasm, wiring, pipeline, startup, manifest, priority-sort, guard-pipeline]

requires:
  - phase: 375-01
    provides: "GuardManifest, load_manifest(), verify_wasm_hash(), verify_abi_version(), WasmGuard receipt metadata"
provides:
  - "load_wasm_guards() manifest-aware sorted guard loading with integrity verification"
  - "build_guard_pipeline() HushSpec-first then WASM pipeline composition"
  - "pub mod wiring re-export from arc-wasm-guards crate root"
affects: [arc-cli, kernel-startup, guard-pipeline-ordering]

tech-stack:
  added: [tempfile (dev)]
  patterns: [tier-ordered-pipeline-composition, advisory-last-sort, manifest-aware-loading]

key-files:
  created:
    - crates/arc-wasm-guards/src/wiring.rs
  modified:
    - crates/arc-wasm-guards/src/lib.rs
    - crates/arc-wasm-guards/Cargo.toml
    - Cargo.toml

key-decisions:
  - "load_wasm_guards sorts by (advisory as u8, priority) so non-advisory guards precede advisory at equal priority, lower priority values run first"
  - "arc-config added as direct dependency for WasmGuardEntry type instead of re-defining it locally"
  - "WasmtimeBackend defaults are used for memory/module-size limits (no .with_limits() call) since WasmGuardEntry does not yet expose those fields"
  - "build_guard_pipeline takes pre-composed guard vectors rather than raw configs to keep composition concerns separated"

requirements-completed: [WGWIRE-01, WGWIRE-02, WGWIRE-03, WGWIRE-04]

duration: 12min
completed: 2026-04-14
---

# Phase 375 Plan 02: Startup Wiring Module Summary

**Manifest-aware guard pipeline wiring with priority sorting, HushSpec-first composition, and full integrity verification at load time**

## Performance

- **Duration:** 12 min
- **Started:** 2026-04-14T22:24:18Z
- **Completed:** 2026-04-14T22:36:18Z
- **Tasks:** 1/1
- **Files modified:** 4

## Accomplishments
- Created wiring.rs module with load_wasm_guards() and build_guard_pipeline() functions
- load_wasm_guards() sorts entries by (advisory, priority), loads guard-manifest.yaml, verifies ABI version, reads .wasm binary, verifies SHA-256 hash, creates WasmtimeBackend with manifest config, and stores manifest wasm_sha256 on WasmGuard for receipt metadata
- build_guard_pipeline() composes HushSpec guards (Tier 1) followed by WASM guards (Tier 2) in a single Vec<Box<dyn Guard>>
- Added arc-config dependency for WasmGuardEntry type
- Added tempfile workspace dev-dependency for filesystem-based tests
- 9 new tests covering priority sorting, advisory ordering, manifest config passthrough, SHA-256 mismatch, unsupported ABI version, missing manifest, and pipeline composition ordering
- All 83 crate tests pass (74 prior + 9 new), clippy clean, no workspace regressions

## Task Commits

Each task was committed atomically:

1. **Task 1: Startup wiring module with manifest-aware pipeline composition** - `cf0174a` (feat)

## Files Created/Modified
- `crates/arc-wasm-guards/src/wiring.rs` - New module: load_wasm_guards(), build_guard_pipeline(), 9 tests
- `crates/arc-wasm-guards/src/lib.rs` - Added pub mod wiring (feature-gated) and re-exports
- `crates/arc-wasm-guards/Cargo.toml` - Added arc-config dependency, tempfile dev-dependency
- `Cargo.toml` - Added tempfile to workspace dependencies

## Decisions Made
- Entries sorted by (advisory as u8, priority) tuple so non-advisory guards precede advisory at equal priority and lower priority values execute first
- arc-config added as direct dependency rather than re-defining WasmGuardEntry locally, keeping a single source of truth for config types
- WasmtimeBackend defaults used for memory/module-size limits since WasmGuardEntry does not yet have those fields
- build_guard_pipeline takes pre-composed Vec<Box<dyn Guard>> for HushSpec and Vec<WasmGuard> for WASM, separating pipeline composition from guard creation concerns

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- Phase 375 is now complete: all guard manifest, receipt metadata, and startup wiring plans landed
- load_wasm_guards() and build_guard_pipeline() are ready for integration into arc-cli startup code
- WasmGuard receipt metadata (manifest_sha256, fuel_consumed) is ready for kernel receipt integration

---
*Phase: 375-guard-manifest-startup-wiring-and-receipt-integration*
*Completed: 2026-04-14*
