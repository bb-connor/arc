---
phase: 374-security-hardening-and-request-enrichment
verified: 2026-04-14T00:00:00Z
status: passed
score: 9/9 must-haves verified
re_verification: false
gaps: []
---

# Phase 374: Security Hardening and Request Enrichment Verification Report

**Phase Goal:** WASM modules are sandboxed against resource abuse and import smuggling, and guards receive host-extracted action context instead of re-deriving it themselves
**Verified:** 2026-04-14
**Status:** passed
**Re-verification:** No -- initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | A WASM guest that attempts to grow linear memory beyond the configured limit is denied by a trap and the guard fails closed | VERIFIED | `WasmHostState::with_memory_limit` calls `trap_on_grow_failure(true)`; test `memory_growth_beyond_limit_traps` passes |
| 2 | A WASM module that imports functions outside the arc namespace is rejected at load time with a clear error | VERIFIED | `load_module` iterates imports and returns `WasmGuardError::ImportViolation` for any non-"arc" module; test `import_validation_rejects_wasi` passes |
| 3 | A WASM module exceeding the configured maximum size is rejected before compilation | VERIFIED | `load_module` checks `wasm_bytes.len() > self.max_module_size` before `Module::new()`; test `module_too_large_rejected` passes |
| 4 | Memory limit, module size limit, and import validation are all configurable via WasmGuardConfig | VERIFIED | `WasmGuardConfig` has `max_memory_bytes` and `max_module_size` with serde defaults; `WasmtimeBackend::with_limits()` builder exists |
| 5 | GuardRequest includes action_type field populated by extract_action() from arc-guards | VERIFIED | `build_request()` calls `arc_guards::extract_action()` and maps to string; test `build_request_action_type_file_access` passes |
| 6 | GuardRequest includes extracted_path for filesystem actions and extracted_target for network egress | VERIFIED | `extracted_path` set from `ToolAction::FileAccess/FileWrite/Patch`; `extracted_target` set from `NetworkEgress`; tests pass |
| 7 | GuardRequest includes filesystem_roots from session context and matched_grant_index from capability scope | VERIFIED | `build_request()` reads `ctx.session_filesystem_roots` and `ctx.matched_grant_index`; tests `build_request_filesystem_roots_from_context` and `build_request_matched_grant_index_from_context` pass |
| 8 | session_metadata field is removed from GuardRequest | VERIFIED | Field absent from `GuardRequest` struct in `abi.rs`; serialized output confirmed not to contain "session_metadata"; test `guard_request_no_session_metadata` passes |
| 9 | Existing WASM guard evaluation still works after field changes | VERIFIED | All 53 tests pass including previous arc_alloc, arc_deny_reason, and mock backend tests |

**Score:** 9/9 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/arc-wasm-guards/src/error.rs` | ImportViolation and ModuleTooLarge error variants | VERIFIED | Both variants present with correct error message formatting and unit tests |
| `crates/arc-wasm-guards/src/config.rs` | max_memory_bytes and max_module_size config fields | VERIFIED | Both fields present with `#[serde(default)]`, default functions return 16 MiB and 10 MiB respectively |
| `crates/arc-wasm-guards/src/host.rs` | WasmHostState::with_memory_limit with trap_on_grow_failure | VERIFIED | `with_memory_limit` uses `StoreLimitsBuilder::new().memory_size(max_memory).trap_on_grow_failure(true).build()` |
| `crates/arc-wasm-guards/src/runtime.rs` | ImportViolation in load_module, configurable limits, extract_action in build_request | VERIFIED | Module size check at line 439, import validation at lines 450-457, `with_memory_limit` at line 471, `extract_action` at line 59 |
| `crates/arc-wasm-guards/Cargo.toml` | arc-guards dependency | VERIFIED | `arc-guards = { package = "arc-guards", path = "../arc-guards" }` present |
| `crates/arc-wasm-guards/src/abi.rs` | Updated GuardRequest with enrichment fields, without session_metadata | VERIFIED | Five new fields present; session_metadata absent from struct definition |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `runtime.rs` | `error.rs` | `WasmGuardError::ImportViolation` and `ModuleTooLarge` used in `load_module` | WIRED | Both error variants used at lines 441 and 452 |
| `runtime.rs` | `host.rs` | `WasmHostState::with_memory_limit` called in `evaluate()` | WIRED | Called at line 471-474 in `WasmtimeBackend::evaluate` |
| `runtime.rs` | `config.rs` | `WasmGuardConfig.max_memory_bytes` and `max_module_size` read by `WasmtimeBackend` | WIRED | `max_module_size` read in `WasmGuardRuntime::load_guard` at line 224; `WasmtimeBackend` fields default from constants matching config defaults |
| `runtime.rs` | `arc-guards/src/action.rs` | `extract_action()` called in `build_request()` | WIRED | `arc_guards::extract_action` called at line 59-62; `ToolAction` variants matched at lines 65-99 |
| `runtime.rs` | `arc-kernel/src/kernel/mod.rs` | `GuardContext.session_filesystem_roots` and `matched_grant_index` read in `build_request()` | WIRED | `ctx.session_filesystem_roots` at line 102; `ctx.matched_grant_index` at line 117 |
| `abi.rs` | `runtime.rs` | `GuardRequest` struct used in `build_request()` and `evaluate()` | WIRED | `GuardRequest` constructed in `build_request` and passed to `backend.evaluate()` |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| WGSEC-01 | 374-01 | ResourceLimiter caps guest linear memory growth (configurable, default 16 MiB) | SATISFIED | `trap_on_grow_failure(true)` in `with_memory_limit`; test `memory_growth_beyond_limit_traps` passes |
| WGSEC-02 | 374-01 | Module import validation rejects modules importing outside arc namespace | SATISFIED | Import loop in `load_module` returns `ImportViolation` for non-"arc" modules; test `import_validation_rejects_wasi` passes |
| WGSEC-03 | 374-01 | Module size validated at load time against configurable maximum | SATISFIED | Pre-`Module::new()` size check in `load_module` and `load_guard`; test `module_too_large_rejected` passes |
| WGREQ-01 | 374-02 | GuardRequest includes action_type pre-extracted by host via extract_action() | SATISFIED | `action_type` field in `GuardRequest`; populated in `build_request()` via `arc_guards::extract_action()` |
| WGREQ-02 | 374-02 | GuardRequest includes extracted_path for filesystem actions | SATISFIED | `extracted_path` field in `GuardRequest`; set for `FileAccess`, `FileWrite`, `Patch` action types |
| WGREQ-03 | 374-02 | GuardRequest includes extracted_target for network egress actions | SATISFIED | `extracted_target` field in `GuardRequest`; set for `NetworkEgress` action type with host string |
| WGREQ-04 | 374-02 | GuardRequest includes filesystem_roots from session context | SATISFIED | `filesystem_roots` field in `GuardRequest`; populated from `ctx.session_filesystem_roots` |
| WGREQ-05 | 374-02 | GuardRequest includes matched_grant_index from capability scope | SATISFIED | `matched_grant_index` field in `GuardRequest`; populated from `ctx.matched_grant_index` |
| WGREQ-06 | 374-02 | session_metadata field removed from GuardRequest | SATISFIED | Field absent from struct; serialization test confirms "session_metadata" never appears in output |

All 9 requirement IDs from PLAN frontmatter accounted for. All map to Phase 374 in the v4.0 traceability table in REQUIREMENTS.md with status "Complete". No orphaned requirements found.

### Anti-Patterns Found

No anti-patterns found. Scan of all modified files:

- No `TODO`, `FIXME`, `PLACEHOLDER` comments in production code paths
- No `return null` / empty stub implementations
- No `unwrap()` or `expect()` in non-test code (`clippy unwrap_used = "deny"` enforced and passes clean)
- `expect()` and `unwrap()` appear only inside `#[cfg(test)]` blocks

### Human Verification Required

None. All behavioral requirements are verified programmatically:

- Memory trap enforcement verified by `memory_growth_beyond_limit_traps` WAT integration test
- Import validation verified by `import_validation_rejects_wasi` WAT integration test
- Module size rejection verified by `module_too_large_rejected` unit test
- Enrichment field population verified by six `build_request_*` unit tests
- session_metadata removal verified by compile-time struct construction and serialization assertion

### Test Results

Full test run output: `cargo test -p arc-wasm-guards --features wasmtime-runtime`

- 53 tests total, 53 passed, 0 failed
- Clippy clean: `cargo clippy -p arc-wasm-guards --features wasmtime-runtime -- -D warnings` exits 0

### Gaps Summary

No gaps. All must-haves from both 374-01 and 374-02 PLAN frontmatter are fully implemented, wired, and tested.

---

_Verified: 2026-04-14_
_Verifier: Claude (gsd-verifier)_
