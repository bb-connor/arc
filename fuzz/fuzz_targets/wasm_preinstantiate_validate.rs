// owned-by: M02 (fuzz lane); target authored under M02.P1.T4.a.
//
//! libFuzzer harness for `chio_wasm_guards::ComponentBackend::load_module`
//! (and the parallel `WasmtimeBackend::load_module` / `detect_wasm_format`
//! preinstantiate-validate entry points).
//!
//! The trust-boundary contract guarantees that arbitrary `.wasm` bytes fed
//! through `ComponentBackend::load_module` (the WASM Component Model
//! preinstantiate-validate path that wraps
//! `wasmtime::component::Component::new`) must surface as
//! `Err(WasmGuardError::*)` rather than a panic, abort, or undefined
//! behavior. This target exists to catch parse-path regressions
//! (unwrap / expect / UB) in the wasmtime / wasmparser chain that hardens
//! the parse + validate stage BEFORE instantiation. Phase 374's
//! `trap_on_grow_failure(true)` enforcement protects the runtime phase;
//! T4.a protects the parse phase.
//!
//! M09 P3 (chio-attest-verify) has merged so the signed-module flow is
//! real, but its `cfg(feature = "attest_verify")` branch sits ABOVE
//! `load_module` in the call graph - the same byte-level entry point is
//! reused once signature verification clears, so this target exercises the
//! exact bytes that downstream signed loads rely on.
//!
//! Input layout: bytes flow unmodified into all three preinstantiate-
//! validate surfaces (`detect_wasm_format`, `ComponentBackend::load_module`,
//! `WasmtimeBackend::load_module`); see
//! `chio_wasm_guards::fuzz::fuzz_wasm_preinstantiate_validate` for the
//! per-surface rationale.
//!
//! `id-token: write` is not relevant here; this is a local fuzz target,
//! not a release workflow.

#![no_main]

use chio_wasm_guards::fuzz::fuzz_wasm_preinstantiate_validate;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_wasm_preinstantiate_validate(data);
});
