// owned-by: M02 (fuzz lane); module authored under M02.P1.T4.a.
//
//! libFuzzer entry-point module for `chio-wasm-guards`.
//!
//! Authored under M02.P1.T4.a (`.planning/trajectory/02-fuzzing-post-pr13.md`
//! Phase 1, trust-boundary fuzz target #8). This module is gated behind the
//! `fuzz` Cargo feature so it only compiles into the standalone `chio-fuzz`
//! workspace at `../../fuzz`. Production builds of `chio-wasm-guards` never
//! pull in `arbitrary`, never expose these symbols, and never get recompiled
//! with libFuzzer instrumentation.
//!
//! # Entry point: `ComponentBackend::load_module`
//!
//! The chosen trust-boundary surface is
//! [`crate::component::ComponentBackend::load_module`], the WASM Component
//! Model preinstantiate-validate path that wraps
//! `wasmtime::component::Component::new`. Every arbitrary byte string fed
//! through this path must surface as `Err(WasmGuardError::*)` (good) rather
//! than a panic, abort, or undefined behavior. The point of this fuzzer is
//! to catch wasmtime-side parse panics (and transitive parser regressions
//! in the `wasm-encoder` / `wasmparser` chain) that reach the host process
//! despite wasmparser's import / type validation.
//!
//! M09 P3 (chio-attest-verify) has merged so the trust boundary is real:
//! signed Component Model modules flow into `ComponentBackend::load_module`
//! after signature verification, but the bytes themselves are still
//! parser-controlled. The signed-module branch is `cfg(feature =
//! "attest_verify")`-gated and is NOT exercised here; T4.a focuses on the
//! unsigned validation path that hardens the parse stage itself.
//!
//! Phase 374 introduced `trap_on_grow_failure(true)` for fail-closed memory
//! enforcement during evaluation. This fuzzer protects the parse-validation
//! phase, not the runtime phase: it stops at `load_module` and never calls
//! `evaluate`, so no guard request is built and no fuel is consumed.
//!
//! # Coverage shape
//!
//! On every iteration the same `data` byte slice is driven through three
//! independent surfaces, all of which share the same wasmparser / wasmtime
//! parse pipeline:
//!
//! 1. [`crate::runtime::wasmtime_backend::detect_wasm_format`] - the format
//!    sniff via `wasmparser::Parser::is_component` /
//!    `Parser::is_core_wasm`. Fail-closed; an `UnrecognizedFormat` error
//!    is the expected outcome for nearly every random input.
//! 2. [`crate::component::ComponentBackend::load_module`] - the
//!    Component Model preinstantiate-validate path. Routes through
//!    `wasmtime::component::Component::new` which performs full Component
//!    Model validation (type imports, world subtype check, alias bounds).
//! 3. [`crate::runtime::wasmtime_backend::WasmtimeBackend::load_module`] -
//!    the core-module preinstantiate-validate path. Routes through
//!    `wasmtime::Module::new` plus the WGSEC-02 import-namespace check.
//!
//! Driving both backend `load_module` paths from the same byte stream keeps
//! coverage symmetric: libFuzzer mutators that converge on a valid core
//! header still get a chance to exercise the component parser (because
//! `Component::new` accepts a wider header set, including the layered
//! component magic), and vice versa.
//!
//! # Process-wide engine cache
//!
//! `wasmtime::Engine::new` allocates JIT machinery and is far too expensive
//! to repeat per fuzz iteration. The engine is built once per process via a
//! `OnceLock`, mirroring the `attest_verify` target's `VERIFIER` pattern.
//! Engine construction is fail-closed: if the embedded wasmtime config
//! cannot build an engine at startup we have no fuzz signal to give and
//! falling through to `return` keeps libFuzzer happy without aborting.

use std::sync::Arc;
use std::sync::OnceLock;

use wasmtime::{Config, Engine};

use crate::abi::WasmGuardAbi;
use crate::component::ComponentBackend;
use crate::runtime::wasmtime_backend::{detect_wasm_format, WasmtimeBackend};

/// Process-wide shared `Engine` for the fuzz harness.
///
/// Mirrors `crate::host::create_shared_engine`: fuel metering on, Component
/// Model on. Built once via `OnceLock` so libFuzzer iterations only pay the
/// JIT-init cost a single time per process. `None` means engine construction
/// failed at startup, in which case [`fuzz_wasm_preinstantiate_validate`]
/// returns immediately and no fuzz signal is produced.
static ENGINE: OnceLock<Option<Arc<Engine>>> = OnceLock::new();

/// Build (or fetch) the process-wide engine. Returns `None` only if the
/// embedded wasmtime config cannot build an engine, which would indicate a
/// link-time mismatch rather than a fuzz finding.
fn engine() -> Option<&'static Arc<Engine>> {
    ENGINE
        .get_or_init(|| {
            let mut config = Config::new();
            config.consume_fuel(true);
            config.wasm_component_model(true);
            Engine::new(&config).ok().map(Arc::new)
        })
        .as_ref()
}

/// Fuel limit handed to `load_module`. The preinstantiate-validate path
/// stores the limit but does not consume fuel; we never call `evaluate`.
/// A non-zero value avoids any short-circuit on zero-fuel pre-checks.
const FUZZ_FUEL_LIMIT: u64 = 1_000_000;

/// Drive arbitrary bytes through the WASM preinstantiate-validate trust
/// boundary.
///
/// Bytes are forwarded through three independent surfaces:
///
/// 1. `detect_wasm_format` (the wasmparser format sniff).
/// 2. `ComponentBackend::load_module` (Component Model parse + validate).
/// 3. `WasmtimeBackend::load_module` (core module parse + validate +
///    import-namespace check).
///
/// All three are run on every iteration so libFuzzer surfaces parse-path
/// panics in either backend regardless of which branch the format sniff
/// would route to. Errors at every step are silently consumed: the
/// trust-boundary contract guarantees the only outcomes are
/// `Err(WasmGuardError::*)` (good) or a panic / abort (which libFuzzer
/// reports as a crash). The `Ok(_)` branch is rare but not impossible -
/// `WasmtimeBackend::load_module` returns `Ok(())` for any well-formed
/// core module whose imports all live in the `chio` namespace, and the
/// minimal-valid component seed is intended to reach `Ok(())` from the
/// component path. We discard both because the post-condition we care about
/// is "no panic", not "verdict is Allow".
pub fn fuzz_wasm_preinstantiate_validate(data: &[u8]) {
    let Some(engine) = engine() else {
        return;
    };

    // Surface 1: format detection (wasmparser sniff).
    let _ = detect_wasm_format(data);

    // Surface 2: Component Model preinstantiate-validate via
    // `wasmtime::component::Component::new`. `with_engine` reuses the
    // process-wide engine and applies the default 16 MiB / 10 MiB limits;
    // we never call `evaluate` so no `Store` is built and no fuel is
    // consumed.
    let mut component_backend = ComponentBackend::with_engine(Arc::clone(engine));
    let _ = component_backend.load_module(data, FUZZ_FUEL_LIMIT);

    // Surface 3: core module preinstantiate-validate via
    // `wasmtime::Module::new` plus the WGSEC-02 import-namespace check.
    // Same engine reuse pattern.
    let mut wasmtime_backend = WasmtimeBackend::with_engine(Arc::clone(engine));
    let _ = wasmtime_backend.load_module(data, FUZZ_FUEL_LIMIT);
}
