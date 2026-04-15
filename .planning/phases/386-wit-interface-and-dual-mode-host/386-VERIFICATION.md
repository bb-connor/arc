---
phase: 386-wit-interface-and-dual-mode-host
verified: 2026-04-14T00:00:00Z
status: passed
score: 8/8 must-haves verified
re_verification: false
---

# Phase 386: WIT Interface and Dual-Mode Host Verification Report

**Phase Goal:** Guard authors and SDK toolchains target a stable, versioned WIT contract instead of raw pointer/length ABI conventions, and the host runtime transparently loads both legacy core-WASM modules and new Component Model components
**Verified:** 2026-04-14
**Status:** passed
**Re-verification:** No -- initial verification

## Goal Achievement

### Observable Truths (from ROADMAP.md Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | A WIT package at `wit/arc-guard/world.wit` defines `arc:guard@0.1.0` with `evaluate` function, `guard-request` record, and `verdict` variant | VERIFIED | File exists at 44 lines; contains `package arc:guard@0.1.0`, `interface types` block with `variant verdict`, `record guard-request` (10 fields), `world guard` with `export evaluate` |
| 2 | Host runtime uses `wasmtime::component::bindgen!` to generate Rust types and evaluates Component Model guards without manual ABI glue | VERIFIED | `component.rs` line 21-24: `wasmtime::component::bindgen!({path: "../../wit/arc-guard", world: "guard"})`. `Guard::instantiate()` used at line 119. Type conversion helpers `to_wit_request()` and `from_wit_verdict()` use generated types, not manual structs |
| 3 | Host detects core module vs Component Model at load time; existing raw-ABI guards continue to work unchanged | VERIFIED | `detect_wasm_format()` in `runtime.rs:382` uses `wasmparser::Parser::is_component()` / `is_core_wasm()`. `create_backend()` at line 399 routes to `WasmtimeBackend` (core) or `ComponentBackend` (component). 86+9 tests pass including existing core-module tests |
| 4 | WIT package under `wit/arc-guard/` includes versioned world with doc comments consumable by SDK toolchains | VERIFIED | `world.wit` has triple-slash doc comments on all types, fields, and the world itself. `arc:guard@0.1.0` version string present. Types in `interface types` block following WIT spec |

**Score:** 4/4 success criteria verified

### Plan 01 Must-Haves (Additional)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 5 | WIT package at `wit/arc-guard/world.wit` defines `arc:guard@0.1.0` with all required types | VERIFIED | Same as truth 1 above |
| 6 | `wasmtime::component::bindgen!` generates Rust types from WIT at compile time | VERIFIED | `cargo check` succeeds in 0.27s; `cargo clippy -D warnings` clean |
| 7 | `ComponentBackend` implements `WasmGuardAbi` and evaluates Component Model guards through generated bindings | VERIFIED | `component.rs:78`: `impl WasmGuardAbi for ComponentBackend`. All four trait methods implemented with proper error handling and no `unwrap()`/`expect()` |
| 8 | Shared Engine has `wasm_component_model(true)` enabled | VERIFIED | `host.rs:87`: `config.wasm_component_model(true);` before `Engine::new(&config)` |

**Combined Score:** 8/8 must-haves verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `wit/arc-guard/world.wit` | WIT package definition for `arc:guard@0.1.0` | VERIFIED | 44 lines, contains package declaration, interface types block, all 10 guard-request fields, verdict variant, world guard with export evaluate |
| `crates/arc-wasm-guards/src/component.rs` | Component Model backend with `bindgen!`-generated types | VERIFIED | 176 lines (exceeds 80-line minimum), exports `ComponentBackend`, contains `bindgen!` macro |
| `crates/arc-wasm-guards/src/runtime.rs` | Dual-mode detection via `WasmFormat`, `detect_wasm_format()`, `create_backend()` | VERIFIED | All three items in `pub mod wasmtime_backend` at lines 348-1370, feature-gated |
| `crates/arc-wasm-guards/src/host.rs` | Engine config with component model enabled | VERIFIED | `wasm_component_model(true)` at line 87, additive to existing `consume_fuel(true)` |
| `crates/arc-wasm-guards/src/lib.rs` | Re-exports `component` module, `ComponentBackend`, `WasmFormat`, `create_backend`, `detect_wasm_format` | VERIFIED | All five re-exports present at lines 48-68, all gated on `wasmtime-runtime` feature |
| `crates/arc-wasm-guards/src/error.rs` | `WasmGuardError::UnrecognizedFormat` variant | VERIFIED | Variant at line 72 with display message "unrecognized WASM format: neither core module nor component" |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `component.rs` | `wit/arc-guard/world.wit` | `bindgen!` macro at compile time | WIRED | `bindgen!({path: "../../wit/arc-guard", world: "guard"})` at line 21; `cargo check` confirms macro resolves at compile time |
| `component.rs` | `crates/arc-wasm-guards/src/abi.rs` | `to_wit_request()` / `from_wit_verdict()` | WIRED | `fn to_wit_request(req: &crate::abi::GuardRequest) -> GuardRequest` at line 152; `fn from_wit_verdict(v: Verdict) -> GuardVerdict` at line 169 |
| `runtime.rs` | `wasmparser::Parser` | `Parser::is_component()` and `Parser::is_core_wasm()` | WIRED | Lines 383-386: `wasmparser::Parser::is_component(bytes)`, `wasmparser::Parser::is_core_wasm(bytes)` |
| `runtime.rs` | `component.rs` | `ComponentBackend::with_engine` in `create_backend()` | WIRED | Line 414: `crate::component::ComponentBackend::with_engine(engine)` |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| WIT-01 | 386-01-PLAN.md | Guard WIT interface defined (`arc:guard@0.1.0`) with `evaluate` function, `guard-request` record, and `verdict` variant types | SATISFIED | `wit/arc-guard/world.wit` contains all required definitions |
| WIT-02 | 386-01-PLAN.md | Host implements the WIT interface using `wasmtime::component::bindgen!` with generated Rust types | SATISFIED | `component.rs` uses `bindgen!` macro and `Guard::instantiate()` / `call_evaluate()` |
| WIT-03 | 386-02-PLAN.md | Host supports dual-mode loading: raw core-WASM modules (legacy ABI) and Component Model components (WIT ABI) detected at load time | SATISFIED | `detect_wasm_format()` and `create_backend()` in `runtime.rs::wasmtime_backend` |
| WIT-04 | 386-01-PLAN.md | WIT package published in-repo under `wit/arc-guard/` with versioned world definition | SATISFIED | `wit/arc-guard/world.wit` exists at workspace root with versioned package `arc:guard@0.1.0` |

**Note on traceability discrepancy:** `REQUIREMENTS.md` traceability table (lines 3418-3421) maps WIT-01 through WIT-04 to "Phase 381" -- but Phase 381 directory is `381-claim-gate-qualification`, which has no relationship to WIT. The ROADMAP.md correctly maps all four requirements to Phase 386. The REQUIREMENTS.md traceability table contains a stale phase number and should be updated to reference Phase 386. This is a documentation issue, not an implementation gap.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| None | -- | -- | -- | No anti-patterns found in phase 386 files |

Scan results:
- No TODO/FIXME/PLACEHOLDER/HACK comments in any phase 386 files
- No `return null` / empty return stubs
- No `unwrap()` or `expect()` in production code in `component.rs`, `host.rs`, or the `wasmtime_backend` module functions (only in `#[cfg(test)]` blocks, which are allowed by the crate-level `cfg_attr`)
- `cargo check -p arc-wasm-guards --features wasmtime-runtime` succeeds (0.27s)
- `cargo clippy -p arc-wasm-guards --features wasmtime-runtime -- -D warnings` clean
- 86 unit tests + 9 integration tests pass
- Formatting issues detected by `cargo fmt --all -- --check` are in pre-existing crates (`arc-api-protect`, `arc-http-core`, `arc-tower`, `arc-wasm-guards/tests/example_guard_integration.rs`, `examples/guards/enriched-inspector`) -- all last modified before phase 386 commits

**Pre-existing workspace issue:** `arc-mercury` fails `cargo check --workspace` with an unrelated function argument count error (last touched in phase 304). This pre-dates phase 386 and does not affect the phase 386 deliverables.

### Human Verification Required

None -- all goal criteria can be verified statically:
- WIT file content and structure is directly readable
- `bindgen!` wiring is confirmed by successful `cargo check`
- Dual-mode routing logic is code-level verifiable
- Test suite (86 unit + 9 integration) covers both backend paths

---

_Verified: 2026-04-14_
_Verifier: Claude (gsd-verifier)_
