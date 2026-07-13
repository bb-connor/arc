//! Integration tests for the TypeScript guard SDK round trip.
//!
//! Loads the TypeScript-compiled `tool-gate.wasm` (built by `jco componentize`)
//! into the Chio host dual-mode WASM runtime and verifies correct Allow/Deny
//! verdicts.
//!
//! Proves the full SDK-to-host round trip: WIT type generation via `jco types`,
//! TypeScript guard compiled via `esbuild` + `jco componentize`, host
//! auto-detection of Component Model format, and correct verdict evaluation
//! through `ComponentBackend`.
//!
//! The TypeScript guard mirrors the Rust `tool-gate` example: it allows any
//! tool not on the deny list (`dangerous_tool`, `rm_rf`, `drop_database`) and
//! returns a deny reason containing "blocked by policy" for blocked tools.
//!
#![cfg(feature = "wasmtime-runtime")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;

use chio_wasm_guards::abi::{GuardRequest, GuardVerdict, WasmGuardAbi};
use chio_wasm_guards::host::create_shared_engine;
use chio_wasm_guards::{create_backend, detect_wasm_format, ComponentBackend, WasmFormat};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Maximum module size for TypeScript-compiled WASM components.
///
/// The `jco componentize` output includes the SpiderMonkey JS engine, which
/// produces binaries around 11 MiB. This exceeds the default 10 MiB
/// `max_module_size` on `ComponentBackend`, so we raise the limit to 15 MiB.
const TS_MAX_MODULE_SIZE: usize = 15 * 1024 * 1024;

/// Maximum memory for the TypeScript component runtime (16 MiB, same as default).
const TS_MAX_MEMORY: usize = 16 * 1024 * 1024;

/// Load the TypeScript-compiled tool-gate guard WASM binary.
fn load_ts_guard_wasm() -> &'static [u8] {
    include_bytes!("../../../../sdks/guard/chio-guard-ts/dist/tool-gate.wasm")
}

/// Create a minimal guard request with only a tool name set.
fn make_request(tool_name: &str) -> GuardRequest {
    GuardRequest {
        tool_name: tool_name.to_string(),
        server_id: "test-server".to_string(),
        agent_id: "test-agent".to_string(),
        arguments: serde_json::json!({}),
        scopes: vec![],
        action_type: None,
        extracted_path: None,
        extracted_target: None,
        filesystem_roots: vec![],
        matched_grant_index: None,
    }
}

#[test]
fn ts_guard_component_round_trip() {
    let wasm_bytes = load_ts_guard_wasm();
    let format = detect_wasm_format(&wasm_bytes).unwrap();
    assert!(
        matches!(format, WasmFormat::Component),
        "expected Component format, got {format:?}"
    );
    let engine = create_shared_engine().unwrap();

    let result = create_backend(engine.clone(), wasm_bytes, 1_000_000_000, HashMap::new());
    assert!(
        result.is_err(),
        "expected create_backend() to reject 11 MiB module with default 10 MiB limit"
    );

    let mut backend =
        ComponentBackend::with_engine(engine).with_limits(TS_MAX_MEMORY, TS_MAX_MODULE_SIZE);
    backend.load_module(wasm_bytes, 1_000_000_000).unwrap();
    assert_eq!(
        backend.backend_name(),
        "wasmtime-component",
        "expected wasmtime-component backend"
    );

    let verdict = backend.evaluate(&make_request("read_file")).unwrap();
    assert!(
        verdict.is_allow(),
        "expected Allow for safe tool 'read_file', got {verdict:?}"
    );

    let verdict = backend.evaluate(&make_request("dangerous_tool")).unwrap();
    assert!(
        verdict.is_deny(),
        "expected Deny for 'dangerous_tool', got {verdict:?}"
    );
    match verdict {
        GuardVerdict::Deny { reason: Some(r) } => {
            assert!(
                r.contains("blocked by policy"),
                "expected reason to contain 'blocked by policy', got: {r}"
            );
        }
        other => panic!("expected Deny with reason, got {other:?}"),
    }

    let verdict = backend.evaluate(&make_request("rm_rf")).unwrap();
    assert!(
        verdict.is_deny(),
        "expected Deny for 'rm_rf', got {verdict:?}"
    );

    let verdict = backend.evaluate(&make_request("drop_database")).unwrap();
    assert!(
        verdict.is_deny(),
        "expected Deny for 'drop_database', got {verdict:?}"
    );
}
