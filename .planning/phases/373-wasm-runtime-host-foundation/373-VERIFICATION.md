---
phase: 373-wasm-runtime-host-foundation
verified: 2026-04-14T21:20:00Z
status: passed
score: 9/9 must-haves verified
re_verification: false
---

# Phase 373: WASM Runtime Host Foundation Verification Report

**Phase Goal:** WASM guards execute inside a proper host environment with shared engine resources, typed host state, and callable host functions
**Verified:** 2026-04-14T21:20:00Z
**Status:** passed
**Re-verification:** No -- initial verification

## Goal Achievement

### Observable Truths (from Plan 01 must_haves)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | All WASM guards loaded by WasmGuardRuntime share one wasmtime Engine instance via Arc<Engine> | VERIFIED | `WasmtimeBackend.engine: Arc<Engine>` in runtime.rs:281; `with_engine(Arc<Engine>)` constructor at runtime.rs:307; `create_shared_engine()` returns `Arc<Engine>` in host.rs:75 |
| 2 | A WASM guest can call arc.log and the host captures the message in a bounded log buffer and emits it via tracing | VERIFIED | host.rs:102-149 registers `func_wrap("arc","log",...)` that buffers to `state.logs` and emits via `tracing::{trace,debug,info,warn,error}`; test `host_log_captures_message` passes |
| 3 | A WASM guest can call arc.get_config and receive config values from WasmHostState | VERIFIED | host.rs:154-212 registers `func_wrap("arc","get_config",...)` that reads from `state.config`; test `host_get_config_reads_value` passes |
| 4 | A WASM guest can call arc.get_time_unix_secs and receive a wall-clock timestamp | VERIFIED | host.rs:217-228 registers `func_wrap("arc","get_time_unix_secs",...)` returning `SystemTime::now().duration_since(UNIX_EPOCH)`; test `host_get_time_returns_positive_value` passes |
| 5 | WasmHostState carries per-guard config HashMap and a bounded Vec of log entries | VERIFIED | host.rs:40-63: `pub struct WasmHostState { config: HashMap<String,String>, logs: Vec<(i32,String)>, max_log_entries: usize, limits: StoreLimits }`; `MAX_LOG_ENTRIES=256` enforced in closure; test `host_log_buffer_respects_max_entries` passes |

### Observable Truths (from Plan 02 must_haves)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 6 | A WASM guest exporting arc_alloc receives request data at the guest-allocated address instead of offset 0 | VERIFIED | runtime.rs:390-428 probes `get_typed_func::<i32,i32>("arc_alloc").ok()`, validates bounds, uses returned ptr; test `arc_alloc_used_when_exported` passes |
| 7 | A WASM guest without arc_alloc still works via the offset-0 fallback | VERIFIED | runtime.rs:425-428 uses `0` when export absent; test `no_arc_alloc_uses_offset_zero` passes |
| 8 | A WASM guest exporting arc_deny_reason returns structured deny reasons to the host | VERIFIED | runtime.rs:461-474 probes `get_typed_func::<(i32,i32),i32>("arc_deny_reason").ok()`, calls `read_structured_deny_reason`; test `arc_deny_reason_structured` passes |
| 9 | A WASM guest without arc_deny_reason falls back to offset-64K NUL-terminated string convention | VERIFIED | runtime.rs:469-471 calls `read_deny_reason` when export absent; test `arc_deny_reason_fallback_legacy` passes; buggy/invalid arc_deny_reason returns None (test `arc_deny_reason_invalid_returns_none` passes) |

**Score:** 9/9 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/arc-wasm-guards/src/host.rs` | WasmHostState struct, host function registration, log buffer constants | VERIFIED | File exists, 566 lines; contains `pub struct WasmHostState`, `create_shared_engine()`, `register_host_functions()`, `MAX_LOG_ENTRIES=256`, `MAX_MEMORY_BYTES=16*1024*1024`, `MAX_LOG_MESSAGE_LEN=4096` |
| `crates/arc-wasm-guards/src/runtime.rs` | Refactored WasmtimeBackend using Arc<Engine> and Store<WasmHostState> | VERIFIED | `engine: Arc<Engine>` at line 281; `Store::new(&self.engine, host_state)` at line 366; `store.limiter(...)` at line 367; `Linker::<WasmHostState>::new` at line 373; no `Store::<()>` present |
| `crates/arc-wasm-guards/src/error.rs` | HostFunction error variant | VERIFIED | `HostFunction(String)` at error.rs:39-40 |
| `crates/arc-wasm-guards/src/lib.rs` | pub mod host, pub use host::WasmHostState | VERIFIED | lib.rs:36-44: `#[cfg(feature = "wasmtime-runtime")] pub mod host;` and `pub use host::WasmHostState;` |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| runtime.rs | host.rs | WasmtimeBackend uses WasmHostState in Store and calls register_host_functions | WIRED | runtime.rs:271 `use crate::host::{create_shared_engine, register_host_functions, WasmHostState};`; called at lines 365, 367, 373-374 |
| host.rs | wasmtime::Linker | func_wrap calls for arc.log, arc.get_config, arc.get_time_unix_secs | WIRED | host.rs:102 `func_wrap("arc","log",...)`, line 154 `func_wrap("arc","get_config",...)`, line 217 `func_wrap("arc","get_time_unix_secs",...)` |
| runtime.rs evaluate() | guest arc_alloc export | get_typed_func::<i32,i32>(&mut store, "arc_alloc") | WIRED | runtime.rs:390-428; bounds check using `saturating_add` at line 402; fallback to 0 on OOB or failure |
| runtime.rs evaluate() | guest arc_deny_reason export | get_typed_func::<(i32,i32),i32>(&mut store, "arc_deny_reason") | WIRED | runtime.rs:462-474; `read_structured_deny_reason` function at lines 512-543; JSON parse then UTF-8 fallback |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|---------|
| WGRT-01 | 373-01 | Shared Arc<Engine> across all guards | SATISFIED | `WasmtimeBackend.engine: Arc<Engine>`; `with_engine()` constructor; `create_shared_engine()` |
| WGRT-02 | 373-01 | WasmHostState in Store with config and log buffer | SATISFIED | `Store<WasmHostState>` throughout evaluate(); `WasmHostState::new(self.config.clone())` per call |
| WGRT-03 | 373-01 | arc.log host function | SATISFIED | `func_wrap("arc","log",...)` in host.rs; tracing emission; bounded buffer; 4 WAT tests cover all edge cases |
| WGRT-04 | 373-01 | arc.get_config host function | SATISFIED | `func_wrap("arc","get_config",...)` in host.rs; reads from `state.config`; -1 sentinel on missing key; WAT tests pass |
| WGRT-05 | 373-01 | arc.get_time_unix_secs host function | SATISFIED | `func_wrap("arc","get_time_unix_secs",...)` in host.rs; returns wall-clock secs; WAT test asserts > 0 |
| WGRT-06 | 373-02 | arc_alloc guest export probing with offset-0 fallback | SATISFIED | `get_typed_func::<i32,i32>("arc_alloc").ok()` in runtime.rs; in-bounds validation; 4 tests cover valid/no-export/OOB/negative cases |
| WGRT-07 | 373-02 | arc_deny_reason guest export probing with legacy fallback | SATISFIED | `get_typed_func::<(i32,i32),i32>("arc_deny_reason").ok()` in runtime.rs; `read_structured_deny_reason` with JSON+UTF-8 parse; 4 tests cover structured/legacy/invalid/absent cases |

All 7 requirements (WGRT-01 through WGRT-07) declared in plan frontmatter are satisfied. REQUIREMENTS.md marks all 7 as Complete under Phase 373. No orphaned requirements found for this phase.

### Anti-Patterns Found

None. Scan of host.rs and runtime.rs production code (outside `#[cfg(test)]` blocks) found:

- Zero `TODO`, `FIXME`, `PLACEHOLDER` comments
- Zero `return null` / empty implementations
- Zero bare `unwrap()` or `expect()` in production code paths (only inside `#[cfg(test)]` blocks, guarded by `#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]` in lib.rs)
- `get_fuel().unwrap_or(0)` at runtime.rs:448 uses `unwrap_or` (not `unwrap`) -- this is a safe fallback, not a panicking call
- `store.limiter(|state| &mut state.limits)` present and activating StoreLimits (WGRT-02 requirement)

### Human Verification Required

None. All must-haves are verifiable programmatically. The test suite ran 32 tests (0 failed), and clippy reported no warnings under `-D warnings`.

### Summary

Phase 373 fully achieves its goal. The codebase contains a proper host execution environment:

1. `host.rs` delivers `WasmHostState` with bounded log buffer and all three host functions registered on a `Linker<WasmHostState>` with no panics in production code.
2. `runtime.rs` WasmtimeBackend is refactored to use `Arc<Engine>` (shared) and `Store<WasmHostState>` (fresh per call) with `store.limiter()` activating resource limits.
3. `arc_alloc` guest export probing is implemented with overflow-safe bounds validation and offset-0 fallback.
4. `arc_deny_reason` guest export probing is implemented with JSON-first parsing, UTF-8 fallback, and legacy offset-64K NUL-string fallback.
5. All 7 requirements (WGRT-01 through WGRT-07) are satisfied, with 32 WAT-based and mock-based unit tests confirming every code path. Clippy is clean.

---

_Verified: 2026-04-14T21:20:00Z_
_Verifier: Claude (gsd-verifier)_
