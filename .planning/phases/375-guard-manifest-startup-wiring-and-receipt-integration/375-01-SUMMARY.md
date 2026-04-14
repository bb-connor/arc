---
phase: 375-guard-manifest-startup-wiring-and-receipt-integration
plan: 01
subsystem: wasm-guards
tags: [wasm, sha256, manifest, fuel-metering, receipt-metadata, yaml, wasmtime]

requires:
  - phase: 373-wasm-host-state-and-host-functions
    provides: "WasmHostState, shared Arc<Engine>, host functions, arc_alloc/arc_deny_reason probing"
  - phase: 374-wasm-security-hardening
    provides: "Import validation, memory limits, module size validation, GuardRequest enrichment"
provides:
  - "GuardManifest struct with YAML deserialization and load_manifest()"
  - "verify_wasm_hash() SHA-256 integrity verification"
  - "verify_abi_version() ABI version gating against SUPPORTED_ABI_VERSIONS"
  - "WasmGuard.manifest_sha256() and last_fuel_consumed() receipt metadata getters"
  - "WasmGuard.guard_evidence_metadata() JSON evidence surface"
  - "WasmtimeBackend fuel consumed tracking per evaluate() call"
  - "WasmGuardAbi.last_fuel_consumed() trait method with default None"
affects: [375-02, guard-wiring, kernel-receipts, arc-config]

tech-stack:
  added: [sha2, hex, serde_yml]
  patterns: [manifest-adjacent-loading, integrity-verified-guard-loading, per-evaluate-fuel-tracking]

key-files:
  created:
    - crates/arc-wasm-guards/src/manifest.rs
  modified:
    - crates/arc-wasm-guards/Cargo.toml
    - crates/arc-wasm-guards/src/error.rs
    - crates/arc-wasm-guards/src/lib.rs
    - crates/arc-wasm-guards/src/runtime.rs
    - crates/arc-wasm-guards/src/abi.rs

key-decisions:
  - "Manifest parsing dependencies (sha2, hex, serde_yml) are NOT feature-gated -- manifest types work without wasmtime"
  - "WasmGuard::new() signature extended with manifest_sha256: Option<String> parameter; all existing callers pass None until Plan 02 wires real values"
  - "Fuel consumed is read within the backend Mutex lock scope before dropping, ensuring no race between evaluate and fuel query"
  - "guard_evidence_metadata() returns a serde_json::Value (not a typed struct) for flexible downstream consumption"

patterns-established:
  - "Manifest-adjacent loading: guard-manifest.yaml resolved from parent directory of .wasm path"
  - "Per-evaluate fuel tracking: WasmtimeBackend stores last_fuel_consumed after each call, WasmGuard reads it within the lock"
  - "Receipt metadata surface: guard_evidence_metadata() provides JSON object with fuel_consumed and manifest_sha256"

requirements-completed: [WGMAN-01, WGMAN-02, WGMAN-03, WGMAN-04, WGRCPT-01, WGRCPT-02]

duration: 16min
completed: 2026-04-14
---

# Phase 375 Plan 01: Guard Manifest and Receipt Metadata Summary

**Guard manifest YAML parsing with SHA-256 integrity verification, ABI version gating, and per-evaluation fuel/hash receipt metadata on WasmGuard**

## Performance

- **Duration:** 16 min
- **Started:** 2026-04-14T22:06:21Z
- **Completed:** 2026-04-14T22:22:20Z
- **Tasks:** 2/2
- **Files modified:** 6

## Accomplishments
- Created manifest.rs module with GuardManifest struct, load_manifest(), verify_wasm_hash(), and verify_abi_version()
- Added four error variants (ManifestParse, ManifestLoad, HashMismatch, UnsupportedAbiVersion) to WasmGuardError
- Extended WasmGuard with manifest_sha256 and last_fuel_consumed fields, plus guard_evidence_metadata() JSON getter
- Extended WasmtimeBackend with per-evaluate fuel consumption tracking
- Added last_fuel_consumed() to WasmGuardAbi trait with default None implementation
- 21 new tests (13 manifest + 8 receipt metadata), 74 total passing, clippy clean, workspace regression-free

## Task Commits

Each task was committed atomically:

1. **Task 1: Guard manifest module and error variants** - `ec32789` (feat)
2. **Task 2: Receipt metadata tracking** - `ed1a5d2` (feat)

**Plan metadata:** [pending] (docs: complete plan)

## Files Created/Modified
- `crates/arc-wasm-guards/src/manifest.rs` - New module: GuardManifest struct, load/verify functions, 13 tests
- `crates/arc-wasm-guards/Cargo.toml` - Added sha2, hex, serde_yml dependencies
- `crates/arc-wasm-guards/src/error.rs` - Four new manifest/hash/ABI error variants
- `crates/arc-wasm-guards/src/lib.rs` - Added pub mod manifest and re-exports
- `crates/arc-wasm-guards/src/runtime.rs` - Extended WasmGuard with metadata fields/getters, fuel tracking in WasmtimeBackend, updated WasmGuard::new() signature
- `crates/arc-wasm-guards/src/abi.rs` - Added last_fuel_consumed() to WasmGuardAbi trait

## Decisions Made
- Manifest parsing dependencies (sha2, hex, serde_yml) are not feature-gated since manifest types should be usable without the wasmtime runtime backend
- WasmGuard::new() signature was extended with manifest_sha256 parameter; existing callers pass None until Plan 02 wires the real manifest loading
- Fuel consumed is read within the backend Mutex lock scope to prevent races between evaluate and fuel query
- guard_evidence_metadata() returns serde_json::Value rather than a typed struct for maximum downstream flexibility

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- Manifest types and verification functions ready for Plan 02 startup wiring
- WasmGuard metadata getters ready for kernel receipt integration
- load_manifest(), verify_wasm_hash(), verify_abi_version() provide the full integrity contract that WasmGuardRuntime::load_guard() will call in Plan 02

---
*Phase: 375-guard-manifest-startup-wiring-and-receipt-integration*
*Completed: 2026-04-14*
