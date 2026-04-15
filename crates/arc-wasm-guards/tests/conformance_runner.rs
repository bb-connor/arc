//! Cross-language conformance runner for WASM guard evaluation.
//!
//! Loads all four language guards (Rust, TypeScript, Python, Go), runs each
//! against every shared YAML fixture, checks verdict correctness, and reports
//! per-guard per-fixture pass/fail in a single invocation.
//!
//! Purpose: Proves cross-language behavioral equivalence -- same policy logic
//! compiled through four different SDK toolchains must produce identical verdicts.
//!
//! Guards that are not compiled (e.g., Go without TinyGo) are gracefully skipped.

#![cfg(feature = "wasmtime-runtime")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use arc_wasm_guards::abi::{GuardRequest, GuardVerdict, WasmGuardAbi};
use arc_wasm_guards::host::create_shared_engine;
use arc_wasm_guards::runtime::wasmtime_backend::WasmtimeBackend;
use arc_wasm_guards::ComponentBackend;
use wasmtime::Engine;

// ---------------------------------------------------------------------------
// TestFixture -- matches the shape from arc-cli/src/guard.rs
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct TestFixture {
    name: String,
    request: GuardRequest,
    expected_verdict: String,
    #[serde(default)]
    deny_reason_contains: Option<String>,
}

// ---------------------------------------------------------------------------
// Guard registry
// ---------------------------------------------------------------------------

/// A loadable guard entry with its WASM bytes and a factory for backends.
struct GuardEntry {
    name: &'static str,
    wasm_bytes: Vec<u8>,
    make_backend: fn(Arc<Engine>, &[u8]) -> Box<dyn WasmGuardAbi>,
}

// ---------------------------------------------------------------------------
// Backend factory functions
// ---------------------------------------------------------------------------

/// Create a WasmtimeBackend (core module) with standard fuel.
fn make_core_backend(engine: Arc<Engine>, wasm_bytes: &[u8]) -> Box<dyn WasmGuardAbi> {
    let mut backend = WasmtimeBackend::with_engine(engine);
    backend.load_module(wasm_bytes, 1_000_000).unwrap();
    Box::new(backend)
}

/// Create a ComponentBackend for TypeScript guards (16 MiB memory, 15 MiB module).
fn make_ts_backend(engine: Arc<Engine>, wasm_bytes: &[u8]) -> Box<dyn WasmGuardAbi> {
    let mut backend =
        ComponentBackend::with_engine(engine).with_limits(16 * 1024 * 1024, 15 * 1024 * 1024);
    backend.load_module(wasm_bytes, 1_000_000_000).unwrap();
    Box::new(backend)
}

/// Create a ComponentBackend for Python guards (64 MiB memory, 40 MiB module).
fn make_py_backend(engine: Arc<Engine>, wasm_bytes: &[u8]) -> Box<dyn WasmGuardAbi> {
    let mut backend =
        ComponentBackend::with_engine(engine).with_limits(64 * 1024 * 1024, 40 * 1024 * 1024);
    backend.load_module(wasm_bytes, 1_000_000_000).unwrap();
    Box::new(backend)
}

/// Create a ComponentBackend for Go guards (16 MiB memory, 10 MiB module).
fn make_go_backend(engine: Arc<Engine>, wasm_bytes: &[u8]) -> Box<dyn WasmGuardAbi> {
    let mut backend =
        ComponentBackend::with_engine(engine).with_limits(16 * 1024 * 1024, 10 * 1024 * 1024);
    backend.load_module(wasm_bytes, 1_000_000_000).unwrap();
    Box::new(backend)
}

// ---------------------------------------------------------------------------
// Guard loaders -- return Option<GuardEntry> (None = graceful skip)
// ---------------------------------------------------------------------------

fn try_load_rust_guard() -> Option<GuardEntry> {
    let path = format!(
        "{}/../../target/wasm32-unknown-unknown/release/arc_example_tool_gate.wasm",
        env!("CARGO_MANIFEST_DIR"),
    );
    let wasm_bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "Rust guard WASM not found at {path}: {e}. \
             Build with: cargo build --target wasm32-unknown-unknown --release -p arc-example-tool-gate"
        )
    });
    Some(GuardEntry {
        name: "rust",
        wasm_bytes,
        make_backend: make_core_backend,
    })
}

fn try_load_ts_guard() -> Option<GuardEntry> {
    let path = format!(
        "{}/../../packages/sdk/arc-guard-ts/dist/tool-gate.wasm",
        env!("CARGO_MANIFEST_DIR"),
    );
    match std::fs::read(&path) {
        Ok(wasm_bytes) => Some(GuardEntry {
            name: "typescript",
            wasm_bytes,
            make_backend: make_ts_backend,
        }),
        Err(_) => None,
    }
}

fn try_load_py_guard() -> Option<GuardEntry> {
    let path = format!(
        "{}/../../packages/sdk/arc-guard-py/dist/tool-gate.wasm",
        env!("CARGO_MANIFEST_DIR"),
    );
    match std::fs::read(&path) {
        Ok(wasm_bytes) => Some(GuardEntry {
            name: "python",
            wasm_bytes,
            make_backend: make_py_backend,
        }),
        Err(_) => None,
    }
}

fn try_load_go_guard() -> Option<GuardEntry> {
    let path = format!(
        "{}/../../packages/sdk/arc-guard-go/dist/tool-gate.wasm",
        env!("CARGO_MANIFEST_DIR"),
    );
    match std::fs::read(&path) {
        Ok(wasm_bytes) => Some(GuardEntry {
            name: "go",
            wasm_bytes,
            make_backend: make_go_backend,
        }),
        Err(_) => None,
    }
}

// ---------------------------------------------------------------------------
// Fixture loading
// ---------------------------------------------------------------------------

fn load_fixtures(relative_path: &str) -> Vec<TestFixture> {
    let path = format!(
        "{}/../../tests/conformance/fixtures/guard/{relative_path}",
        env!("CARGO_MANIFEST_DIR"),
    );
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read fixture file {path}: {e}"));
    serde_yml::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse fixture file {path}: {e}"))
}

// ---------------------------------------------------------------------------
// Verdict checking
// ---------------------------------------------------------------------------

fn check_verdict(fixture: &TestFixture, verdict: &GuardVerdict) -> Result<(), String> {
    match fixture.expected_verdict.as_str() {
        "allow" => {
            if verdict.is_allow() {
                Ok(())
            } else {
                Err(format!("expected Allow, got {verdict:?}"))
            }
        }
        "deny" => match verdict {
            GuardVerdict::Deny { reason } => {
                if let Some(ref expected_substr) = fixture.deny_reason_contains {
                    match reason {
                        Some(r) if r.contains(expected_substr.as_str()) => Ok(()),
                        Some(r) => Err(format!(
                            "deny reason {r:?} does not contain {expected_substr:?}"
                        )),
                        None => Err(format!(
                            "expected deny reason containing {expected_substr:?}, got None"
                        )),
                    }
                } else {
                    Ok(())
                }
            }
            GuardVerdict::Allow => Err("expected Deny, got Allow".to_string()),
        },
        other => Err(format!("unknown expected_verdict: {other:?}")),
    }
}

// ---------------------------------------------------------------------------
// Main conformance test: tool-gate across all languages
// ---------------------------------------------------------------------------

#[test]
fn conformance_tool_gate_all_languages() {
    let fixtures = load_fixtures("tool-gate.yaml");
    let engine = create_shared_engine().unwrap();

    // Build guard registry: Rust is mandatory, others are optional.
    let guard_loaders: Vec<(&str, fn() -> Option<GuardEntry>)> = vec![
        ("rust", try_load_rust_guard as fn() -> Option<GuardEntry>),
        ("typescript", try_load_ts_guard),
        ("python", try_load_py_guard),
        ("go", try_load_go_guard),
    ];

    let mut passed = 0u32;
    let mut failed = 0u32;
    let mut skipped_guards = 0u32;

    for (label, loader) in &guard_loaders {
        let entry = match loader() {
            Some(e) => e,
            None => {
                println!("[SKIP] {label}: guard WASM not found");
                skipped_guards += 1;
                continue;
            }
        };

        for fixture in &fixtures {
            // Fresh backend per fixture for fuel state isolation.
            let mut backend = (entry.make_backend)(engine.clone(), &entry.wasm_bytes);
            let verdict = backend.evaluate(&fixture.request);

            match verdict {
                Ok(ref v) => match check_verdict(fixture, v) {
                    Ok(()) => {
                        println!("[PASS] {} / {}", entry.name, fixture.name);
                        passed += 1;
                    }
                    Err(reason) => {
                        println!("[FAIL] {} / {}: {reason}", entry.name, fixture.name);
                        failed += 1;
                    }
                },
                Err(e) => {
                    println!(
                        "[FAIL] {} / {}: evaluation error: {e}",
                        entry.name, fixture.name
                    );
                    failed += 1;
                }
            }
        }
    }

    let total = passed + failed;
    println!(
        "conformance: {passed}/{total} passed, {skipped_guards} guards skipped"
    );
    assert_eq!(failed, 0, "conformance failures detected");
}

// ---------------------------------------------------------------------------
// Enriched-inspector test: Rust only
// ---------------------------------------------------------------------------

#[test]
fn conformance_enriched_inspector_rust() {
    let fixtures = load_fixtures("enriched-fields.yaml");
    let engine = create_shared_engine().unwrap();

    let path = format!(
        "{}/../../target/wasm32-unknown-unknown/release/arc_example_enriched_inspector.wasm",
        env!("CARGO_MANIFEST_DIR"),
    );
    let wasm_bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "Rust enriched-inspector WASM not found at {path}: {e}. \
             Build with: cargo build --target wasm32-unknown-unknown --release -p arc-example-enriched-inspector"
        )
    });

    let mut passed = 0u32;
    let mut failed = 0u32;

    for fixture in &fixtures {
        // Fresh backend per fixture for fuel state isolation.
        let mut backend = WasmtimeBackend::with_engine(engine.clone());
        backend.load_module(&wasm_bytes, 1_000_000).unwrap();

        let verdict = backend.evaluate(&fixture.request);

        match verdict {
            Ok(ref v) => match check_verdict(fixture, v) {
                Ok(()) => {
                    println!("[PASS] enriched-inspector / {}", fixture.name);
                    passed += 1;
                }
                Err(reason) => {
                    println!("[FAIL] enriched-inspector / {}: {reason}", fixture.name);
                    failed += 1;
                }
            },
            Err(e) => {
                println!(
                    "[FAIL] enriched-inspector / {}: evaluation error: {e}",
                    fixture.name
                );
                failed += 1;
            }
        }
    }

    let total = passed + failed;
    println!("enriched-inspector conformance: {passed}/{total} passed");
    assert_eq!(failed, 0, "enriched-inspector conformance failures detected");
}
