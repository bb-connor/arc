---
phase: 375-guard-manifest-startup-wiring-and-receipt-integration
verified: 2026-04-14T00:00:00Z
status: passed
score: 9/9 must-haves verified
re_verification: false
---

# Phase 375: Guard Manifest Startup Wiring and Receipt Integration Verification Report

**Phase Goal:** Guards load from signed manifests with SHA-256 verification, wire into the kernel pipeline in the correct HushSpec-then-WASM-then-advisory order, and produce auditable receipt metadata
**Verified:** 2026-04-14
**Status:** passed
**Re-verification:** No -- initial verification

---

## Goal Achievement

### Observable Truths

| #  | Truth | Status | Evidence |
|----|-------|--------|----------|
| 1  | A guard-manifest.yaml is parsed into a GuardManifest struct with name, version, abi_version, wasm_path, wasm_sha256, and config fields | VERIFIED | `GuardManifest` struct at `manifest.rs:36-51`; all six fields present; 11 tests covering deserialization |
| 2  | SHA-256 of the actual .wasm binary is verified against declared wasm_sha256; mismatches are rejected | VERIFIED | `verify_wasm_hash()` at `manifest.rs:82-94`; `HashMismatch` variant in `error.rs:63-64`; `wiring.rs` calls it at line 75; wiring test `sha256_mismatch_returns_error` confirms rejection |
| 3  | abi_version is validated against SUPPORTED_ABI_VERSIONS; unsupported versions are rejected | VERIFIED | `verify_abi_version()` at `manifest.rs:97-106`; `SUPPORTED_ABI_VERSIONS = ["1"]`; `UnsupportedAbiVersion` error variant in `error.rs:67-68`; wiring test `unsupported_abi_version_returns_error` confirms rejection |
| 4  | Config values from the manifest's config block feed into WasmHostState and are readable by the guest via arc.get_config | VERIFIED | `wiring.rs:79` passes `guard_manifest.config.clone()` to `WasmtimeBackend::with_engine_and_config()`; `manifest_config_passed_through_to_backend` test confirms this path |
| 5  | After a WASM guard evaluates, fuel_consumed and manifest_sha256 are queryable from the WasmGuard struct | VERIFIED | `WasmGuard::last_fuel_consumed()` at `runtime.rs:78`; `WasmGuard::manifest_sha256()` at `runtime.rs:70`; `guard_evidence_metadata()` at `runtime.rs:85`; `WasmtimeBackend::last_fuel_consumed()` impl at `runtime.rs:645`; fuel stored after evaluate at `runtime.rs:597-599`; 6 receipt-metadata unit tests at lines 1640-1734 |
| 6  | Startup code loads HushSpec guards first, then WASM guards sorted by (advisory, priority) | VERIFIED | `build_guard_pipeline()` in `wiring.rs:109-124` extends hushspec guards first then WASM guards; `load_wasm_guards()` sorts by `(e.advisory as u8, e.priority)` at `wiring.rs:57`; tests `entries_sorted_by_priority_before_loading` and `advisory_guards_placed_after_non_advisory_at_same_priority` confirm ordering |
| 7  | Missing guard-manifest.yaml returns a ManifestLoad error identifying the path | VERIFIED | `load_manifest()` returns `WasmGuardError::ManifestLoad` with path at `manifest.rs:71-74`; `missing_manifest_returns_error_with_path` test in wiring confirms error contains "guard-manifest.yaml" |
| 8  | wiring.rs is feature-gated under wasmtime-runtime and re-exported from lib.rs | VERIFIED | `lib.rs:40-41` has `#[cfg(feature = "wasmtime-runtime")] pub mod wiring;`; `lib.rs:50-51` re-exports `build_guard_pipeline` and `load_wasm_guards` under same flag |
| 9  | manifest.rs is NOT feature-gated (manifest types usable without wasmtime) | VERIFIED | `lib.rs:38` declares `pub mod manifest;` with no cfg gate; `lib.rs:48` re-exports `GuardManifest`, `MANIFEST_FILENAME`, `SUPPORTED_ABI_VERSIONS` without feature gate |

**Score:** 9/9 truths verified

---

## Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/arc-wasm-guards/src/manifest.rs` | GuardManifest struct, load_manifest(), verify_wasm_hash(), verify_abi_version() | VERIFIED | 335 lines; all four public items present; 11 tests; no stubs |
| `crates/arc-wasm-guards/src/error.rs` | ManifestParse, ManifestLoad, HashMismatch, UnsupportedAbiVersion error variants | VERIFIED | All four variants at lines 54-68; display strings match spec exactly |
| `crates/arc-wasm-guards/src/runtime.rs` | WasmGuard with manifest_sha256, last_fuel_consumed, guard_evidence_metadata; WasmtimeBackend fuel tracking | VERIFIED | All getters present; fuel tracked at lines 597-599 and 645-646; WasmGuard::new() accepts manifest_sha256 at line 51 |
| `crates/arc-wasm-guards/src/abi.rs` | last_fuel_consumed() default method on WasmGuardAbi trait | VERIFIED | Default method at lines 114-116 returning None |
| `crates/arc-wasm-guards/src/wiring.rs` | load_wasm_guards(), build_guard_pipeline(), priority sort, manifest wiring | VERIFIED | Both public functions present; sort at line 57; all 7 wiring tests present |
| `crates/arc-wasm-guards/src/lib.rs` | pub mod manifest (ungated), pub mod wiring (feature-gated), re-exports | VERIFIED | Declarations at lines 38 and 40-41; re-exports at lines 48 and 50-51 |
| `crates/arc-wasm-guards/Cargo.toml` | sha2, hex, serde_yml dependencies (not feature-gated) | VERIFIED | All three deps present at lines 24, 23, 26 under [dependencies]; not under wasmtime feature |

---

## Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `manifest.rs` | `error.rs` | WasmGuardError::ManifestParse, ManifestLoad, HashMismatch, UnsupportedAbiVersion | WIRED | All four variants referenced in manifest.rs at lines 64, 72, 88-91, 101-104 |
| `runtime.rs` | `manifest.rs` | manifest_sha256 field on WasmGuard, WasmtimeBackend fuel tracking | WIRED | manifest_sha256 field at runtime.rs:36; fuel tracking at lines 597-599, 645-646 |
| `wiring.rs` | `manifest.rs` | load_manifest(), verify_abi_version(), verify_wasm_hash() | WIRED | All three called in wiring.rs at lines 63, 66, 75; `use crate::manifest;` at line 35 |
| `wiring.rs` | `runtime.rs` | WasmGuard::new() with manifest_sha256, WasmtimeBackend::with_engine_and_config() | WIRED | WasmGuard::new() at wiring.rs:85-90; WasmtimeBackend::with_engine_and_config() at wiring.rs:79 |
| `wiring.rs` | `manifest.rs` | manifest.config feeds into WasmHostState via backend constructor | WIRED | `guard_manifest.config.clone()` passed at wiring.rs:79 |

---

## Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| WGMAN-01 | 375-01 | guard-manifest.yaml format: name, version, abi_version, wasm path, config, wasm_sha256 | SATISFIED | GuardManifest struct with all six fields in manifest.rs |
| WGMAN-02 | 375-01 | Host verifies wasm_sha256 against actual .wasm content at load time | SATISFIED | verify_wasm_hash() in manifest.rs; called in wiring.rs load path |
| WGMAN-03 | 375-01 | Host validates abi_version; rejects unsupported | SATISFIED | verify_abi_version() in manifest.rs; called in wiring.rs; SUPPORTED_ABI_VERSIONS = ["1"] |
| WGMAN-04 | 375-01 | Guard config from manifest available via arc.get_config | SATISFIED | manifest.config.clone() passed to WasmtimeBackend::with_engine_and_config() in wiring.rs |
| WGWIRE-01 | 375-02 | Startup loads HushSpec guards via compile_policy(), registers them first | SATISFIED | build_guard_pipeline() puts hushspec_guards first via pipeline.extend(hushspec_guards) |
| WGWIRE-02 | 375-02 | Startup sorts WasmGuardEntry list by priority before loading | SATISFIED | sorted.sort_by_key(|e| (e.advisory as u8, e.priority)) in load_wasm_guards() |
| WGWIRE-03 | 375-02 | WASM guards registered after HushSpec, before advisory pipeline | SATISFIED | Pipeline ordering in build_guard_pipeline(); advisory WASM guards placed last by sort key |
| WGWIRE-04 | 375-02 | guard-manifest.yaml loaded adjacent to each .wasm path; config passed to WasmHostState | SATISFIED | load_manifest(&entry.path) + config passthrough in load_wasm_guards() |
| WGRCPT-01 | 375-01 | Fuel consumed recorded and available in receipt metadata | SATISFIED | WasmtimeBackend tracks last_fuel_consumed; WasmGuard::last_fuel_consumed() getter; guard_evidence_metadata() exposes it |
| WGRCPT-02 | 375-01 | Guard manifest SHA-256 recorded and available in receipt metadata | SATISFIED | WasmGuard stores manifest_sha256 at construction; manifest_sha256() getter; guard_evidence_metadata() exposes it |

All 10 requirements declared in plan frontmatter are SATISFIED. REQUIREMENTS.md traceability table marks all 10 as Complete for Phase 375 (lines 3135-3144).

No orphaned requirements found -- REQUIREMENTS.md maps exactly these 10 IDs to Phase 375.

---

## Anti-Patterns Found

| File | Pattern | Severity | Impact |
|------|---------|----------|--------|
| `runtime.rs:260` | `None, // manifest_sha256 -- Plan 02 will pass the real value` | Info | Comment is accurate -- this is `WasmGuardRuntime::load_guard()` which is the legacy path; Plan 02's `load_wasm_guards()` passes real SHA-256. Not a blocker. |

No TODO/FIXME/PLACEHOLDER comments in production code. No empty return stubs (`return null`, `return {}`, `return []`). No handler-only-prevents-default patterns. No queries returning static values instead of results.

---

## Human Verification Required

None. All behaviors are structurally verifiable through code inspection:

- Pipeline ordering is enforced by the sort key `(advisory as u8, priority)` and sequential Vec extension in `build_guard_pipeline()`.
- SHA-256 verification is a deterministic hash comparison.
- Fuel tracking writes to a `Mutex<Option<u64>>` field that is read by the public getter.
- Config passthrough is a direct clone of `HashMap<String, String>` at construction time.

---

## Gaps Summary

No gaps. All nine observable truths verified, all seven artifacts substantive and wired, all five key links confirmed, all ten requirements satisfied.

---

_Verified: 2026-04-14T00:00:00Z_
_Verifier: Claude (gsd-verifier)_
