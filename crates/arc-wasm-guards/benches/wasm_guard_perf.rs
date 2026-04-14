#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Performance benchmarks for the arc-wasm-guards WASM guard runtime.
//!
//! Run with:
//!   cargo bench --bench wasm_guard_perf --features wasmtime-runtime
//!
//! Benchmark groups:
//! - wasm_guards/compilation: Module::new() compilation time for 50 KiB and 5 MiB WAT modules
//! - wasm_guards/instantiation: Linker::instantiate() per-call overhead with pre-compiled module

use std::collections::HashMap;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use wasmtime::{Linker, Module, Store};

use arc_wasm_guards::host::{create_shared_engine, register_host_functions, WasmHostState};

// ---------------------------------------------------------------------------
// WAT module builder helpers
// ---------------------------------------------------------------------------

/// Returns a minimal WAT module that imports all three arc.* host functions,
/// exports memory (1 page) and `evaluate` returning VERDICT_ALLOW (0).
/// Approximately 200 bytes compiled. Used for instantiation benchmarks.
fn build_trivial_guard_wat() -> &'static str {
    r#"(module
    (import "arc" "log" (func $log (param i32 i32 i32)))
    (import "arc" "get_config" (func $gc (param i32 i32 i32 i32) (result i32)))
    (import "arc" "get_time_unix_secs" (func $gt (result i64)))
    (memory (export "memory") 1)
    (func (export "evaluate") (param i32 i32) (result i32)
        (i32.const 0)
    )
)"#
}

/// Builds a WAT module with a `(data ...)` segment padded with null bytes to
/// approximate the target compiled binary size.
///
/// The data segment uses `\00` bytes repeated to reach the target size minus
/// approximate WAT overhead for imports/exports/header (~300 bytes). Memory
/// pages are sized to fit the data segment.
///
/// Note: WAT data segments produce roughly 1:1 binary size for the data
/// payload. Accept approximate sizes within ~10% of target.
fn build_sized_wat(target_binary_bytes: usize) -> String {
    let padding_size = target_binary_bytes.saturating_sub(300);
    let padding = "\\00".repeat(padding_size);
    let pages = (target_binary_bytes / 65536) + 1;
    format!(
        r#"(module
    (import "arc" "log" (func $log (param i32 i32 i32)))
    (import "arc" "get_config" (func $gc (param i32 i32 i32 i32) (result i32)))
    (import "arc" "get_time_unix_secs" (func $gt (result i64)))
    (memory (export "memory") {pages})
    (data (i32.const 0) "{padding}")
    (func (export "evaluate") (param i32 i32) (result i32)
        (i32.const 0)
    )
)"#
    )
}

// ---------------------------------------------------------------------------
// Benchmark group 1: Module compilation (WGBENCH-01)
// ---------------------------------------------------------------------------

/// Benchmarks Module::new() compilation time for representative guard sizes.
///
/// - 50 KiB module: validates against the 50ms compilation threshold from
///   docs/guards/05-V1-DECISION.md.
/// - 5 MiB module: documents large-module compilation time (may exceed 50ms;
///   that is expected for very large modules).
fn bench_module_compilation(c: &mut Criterion) {
    let engine = create_shared_engine().unwrap();

    let small_wat = build_sized_wat(50 * 1024); // ~50 KiB target
    let large_wat = build_sized_wat(5 * 1024 * 1024); // ~5 MiB target

    let mut group = c.benchmark_group("wasm_guards/compilation");

    group.bench_function("50kib_module", |b| {
        b.iter(|| {
            let _ = black_box(Module::new(
                black_box(&engine),
                black_box(small_wat.as_bytes()),
            ));
        });
    });

    // Reduce sample size for the slow 5 MiB compilation
    group.sample_size(10);
    group.bench_function("5mib_module", |b| {
        b.iter(|| {
            let _ = black_box(Module::new(
                black_box(&engine),
                black_box(large_wat.as_bytes()),
            ));
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark group 2: Instantiation overhead (WGBENCH-02)
// ---------------------------------------------------------------------------

/// Benchmarks pure `linker.instantiate()` per-call overhead with a
/// pre-compiled trivial guard module.
///
/// The setup closure creates a fresh Store + Linker each iteration (matching
/// production behavior where each evaluate() gets a fresh Store), but the
/// module compilation is excluded from measurement.
fn bench_instantiation(c: &mut Criterion) {
    let engine = create_shared_engine().unwrap();
    let trivial_wat = build_trivial_guard_wat();
    let module = Module::new(&engine, trivial_wat).unwrap();

    let mut group = c.benchmark_group("wasm_guards/instantiation");

    group.bench_function("trivial_guard", |b| {
        b.iter_batched(
            || {
                // Setup: pre-build linker with host functions (isolates
                // instantiation cost from linker setup)
                let host_state = WasmHostState::new(HashMap::new());
                let mut store = Store::new(&engine, host_state);
                store.limiter(|s| &mut s.limits);
                store.set_fuel(10_000_000).unwrap();
                let mut linker = Linker::new(&engine);
                register_host_functions(&mut linker).unwrap();
                (store, linker)
            },
            |(mut store, linker)| {
                // Measured: instantiation only
                let _instance = black_box(linker.instantiate(&mut store, &module).unwrap());
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion entry point
// ---------------------------------------------------------------------------

criterion_group!(benches, bench_module_compilation, bench_instantiation,);
criterion_main!(benches);
