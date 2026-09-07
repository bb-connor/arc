// Threat test for threat ID `tool_server_escape`.
//
// Threat: tool_server_escape (Tool server escape).
// Surfaces: kernel_to_tool.
//
// Coverage strategy: import the production
// `chio_wasm_guards::runtime::wasmtime_backend::WasmtimeBackend`
// directly. The threat row's stable production defense is the
// runtime sandbox enforced by chio-wasm-guards: a malicious tool
// module signed by an attacker-controlled key still trips a typed
// `WasmGuardError` because the runtime layer rejects undeclared host
// imports, oversize declared memory, and fuel-budget overrun
// independently of the signing layer (the signing layer only
// certifies provenance, never content).
//
// The actual sandbox-escape containment lives in chio-wasm-guards, not
// in the signing or kernel dispatch layer. This conformance test
// pins the production runtime deny path that catches a malicious
// tool module at module-load and at evaluate-time. The same test file also
// drives attacker-controlled connections through the hosted kernel and
// exercises the portable verified-core matcher with the same pivots. Five
// sub-vectors:
//
//   1. Undeclared host import. The module imports a host function
//      that is NOT in the chio.* allowed surface (`wasi_snapshot_preview1.fd_write`).
//      Production `load_module` MUST reject with
//      `WasmGuardError::ImportViolation` before any guest code runs.
//   2. Fuel-budget escape attempt. The module spins in a tight loop
//      to exhaust the host process's CPU budget. Production
//      `evaluate` MUST trap and return `WasmGuardError::FuelExhausted`
//      (or `Trap`) before the loop completes.
//   3. Round-trip sanity. A trivially benign module that exports
//      `evaluate` and returns `Allow` MUST verify successfully,
//      guarding against an over-rejecting deny path that would
//      silently classify all tool modules as escapes.
//   4. Tool pivot. A permissive connection advertises an admitted tool and
//      a privileged tool. A capability for the admitted tool MUST NOT invoke
//      the privileged tool after a positive control proves the connection is
//      reachable for the admitted tool. The portable matcher MUST return the
//      same deny verdict.
//   5. Server pivot. A second permissive connection advertises the admitted
//      tool under another server identity. A capability for the first server
//      MUST NOT invoke the second server. The portable matcher MUST return the
//      same deny verdict.
//
// Production call sites:
//   `crates/guards/chio-wasm-guards/src/runtime.rs:1167`
//     (`WasmtimeBackend::load_module`).
//   `crates/guards/chio-wasm-guards/src/runtime.rs:1202`
//     (`WasmtimeBackend::evaluate`).
//   `crates/kernel/chio-kernel/src/kernel/evaluation/evaluation_entry.rs`
//     (`ChioKernel::evaluate_tool_call`).
//   `crates/kernel/chio-kernel/src/kernel/dispatch.rs`
//     (`ChioKernel::invoke_resolved_server`).
//   `crates/chio-kernel-core/src/scope.rs`
//     (`resolve_matching_grants`).
//
// Cross-link: the chio-wasm-guards crate ships its own escape harness
// at `crates/guards/chio-wasm-guards/tests/escape/` (8 named escape classes,
// all yielding typed `WasmGuardError`). This conformance test replays
// two of those escape classes through the same production backend so
// the threat row carries both file-existence and runtime evidence.
//
// Revert-to-prove-it-fails recipe:
// In `crates/guards/chio-wasm-guards/src/runtime.rs`, locate the
// `validate_imports` (or equivalently named) helper used by
// `WasmtimeBackend::load_module` to reject non-`chio.*` imports.
// Replace its body with `Ok(())`. Re-run
// `cargo test -p chio-conformance --test threats -- tool_server_escape`
// and the
// `assert!(matches!(err, WasmGuardError::ImportViolation { .. }))`
// arm in `undeclared_host_import_rejected_at_load` MUST then fail
// because production now admits modules with arbitrary host imports.
// For the kernel mediation arm, replace `grant_matches_request` in
// `crates/kernel/chio-kernel/src/request_matching.rs` with `Ok(true)`.
// The pivot denial or unchanged invocation-count assertion MUST fail.
// Replacing `grant_covers` in
// `crates/kernel/chio-kernel-core/src/scope.rs` with `Ok(true)` MUST fail the
// matching portable pivot assertion.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::Keypair;
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolCallRequest, ToolServerConnection,
    Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_kernel_core::{FixedClock, PortableToolCallRequest, Verdict as PortableVerdict};
use chio_wasm_guards::abi::{GuardRequest, WasmGuardAbi};
use chio_wasm_guards::error::WasmGuardError;
use chio_wasm_guards::runtime::wasmtime_backend::WasmtimeBackend;

const ESCAPE_FUEL_LIMIT: u64 = 5_000_000;

fn minimal_request() -> GuardRequest {
    GuardRequest {
        tool_name: String::new(),
        server_id: String::new(),
        agent_id: "tool-server-escape-test".to_string(),
        arguments: serde_json::Value::Null,
        scopes: Vec::new(),
        action_type: None,
        extracted_path: None,
        extracted_target: None,
        filesystem_roots: Vec::new(),
        matched_grant_index: None,
    }
}

struct PermissiveEscapeServer {
    id: &'static str,
    invocations: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl ToolServerConnection for PermissiveEscapeServer {
    fn server_id(&self) -> &str {
        self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["read_public".to_string(), "exec_privileged".to_string()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({
            "escaped": true,
            "tool": tool_name,
            "arguments": arguments,
        }))
    }
}

fn escape_test_kernel() -> ChioKernel {
    ChioKernel::new(KernelConfig {
        keypair: Keypair::from_seed(&[0x51; 32]),
        ca_public_keys: Vec::new(),
        max_delegation_depth: 5,
        policy_hash: "tool-server-escape-mediation-v1".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    })
}

fn admitted_scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "admitted-server".to_string(),
            tool_name: "read_public".to_string(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn escape_request(
    request_id: &str,
    capability: &chio_core::capability::token::CapabilityToken,
    server_id: &str,
    tool_name: &str,
) -> ToolCallRequest {
    ToolCallRequest {
        request_id: request_id.to_string(),
        capability: capability.clone(),
        tool_name: tool_name.to_string(),
        server_id: server_id.to_string(),
        agent_id: capability.subject.to_hex(),
        arguments: serde_json::json!({"path": "/host/root"}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    }
}

fn portable_escape_request(
    request_id: &str,
    capability: &chio_core::capability::token::CapabilityToken,
    server_id: &str,
    tool_name: &str,
) -> PortableToolCallRequest {
    PortableToolCallRequest {
        request_id: request_id.to_string(),
        tool_name: tool_name.to_string(),
        server_id: server_id.to_string(),
        agent_id: capability.subject.to_hex(),
        arguments: serde_json::json!({"path": "/host/root"}),
    }
}

fn current_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[test]
fn threat_tool_server_escape_undeclared_host_import_rejected_at_load() {
    // covers: tool_server_escape
    //
    // Attacker scenario: an attacker controlling a "tool module"
    // imports the wasi `fd_write` host function in an attempt to
    // escape into raw stdout/stderr file descriptors via the
    // wasi-libc shim. Production MUST reject this at module-load
    // before any guest code runs.
    let wat = r#"
        (module
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "evaluate") (param i32 i32) (result i32) (i32.const 0)))
    "#;
    let bytes = match wat::parse_str(wat) {
        Ok(bytes) => bytes,
        Err(err) => panic!("wat compile failed: {err}"),
    };

    let mut backend = match WasmtimeBackend::new() {
        Ok(backend) => backend,
        Err(err) => panic!("WasmtimeBackend::new failed: {err:?}"),
    };
    let err = match backend.load_module(&bytes, ESCAPE_FUEL_LIMIT) {
        Ok(()) => panic!(
            "WasmtimeBackend::load_module MUST reject undeclared host \
             imports (escape via wasi_snapshot_preview1.fd_write); got Ok"
        ),
        Err(err) => err,
    };
    match err {
        WasmGuardError::ImportViolation { module, name } => {
            assert_eq!(module, "wasi_snapshot_preview1");
            assert_eq!(name, "fd_write");
        }
        other => panic!("expected WasmGuardError::ImportViolation on wasi import, got {other:?}"),
    }
}

#[test]
fn threat_tool_server_escape_fuel_exhaustion_attack_traps() {
    // covers: tool_server_escape
    //
    // Attacker scenario: the tool module loads cleanly but its
    // `evaluate` body spins in an infinite loop to denial-of-service
    // the host. Production fuel metering MUST trap with
    // `WasmGuardError::FuelExhausted` (or a fuel-related `Trap`)
    // before the host loses liveness.
    let wat = r#"
        (module
          (memory (export "memory") 1)
          (func (export "evaluate") (param i32 i32) (result i32)
            (loop $forever (br $forever))
            (i32.const 0)))
    "#;
    let bytes = match wat::parse_str(wat) {
        Ok(bytes) => bytes,
        Err(err) => panic!("wat compile failed: {err}"),
    };

    let mut backend = match WasmtimeBackend::new() {
        Ok(backend) => backend,
        Err(err) => panic!("WasmtimeBackend::new failed: {err:?}"),
    };
    if let Err(err) = backend.load_module(&bytes, ESCAPE_FUEL_LIMIT) {
        panic!(
            "infinite-loop module MUST load (the trap fires at evaluate), \
             got load-time error {err:?}"
        );
    }
    let err = match backend.evaluate(&minimal_request()) {
        Ok(verdict) => panic!(
            "WasmtimeBackend::evaluate MUST trap on a fuel-escape module; \
             got verdict {verdict:?}"
        ),
        Err(err) => err,
    };
    match err {
        WasmGuardError::FuelExhausted { .. } | WasmGuardError::Trap(_) => {}
        other => panic!("expected FuelExhausted or fuel-related Trap, got {other:?}"),
    }
}

#[test]
fn threat_tool_server_escape_benign_module_round_trips() {
    // covers: tool_server_escape (sanity)
    //
    // Sanity arm: a benign module that exports `evaluate` and
    // returns `0` (Allow) MUST load and run without error. This
    // guards against an over-rejecting deny path that would silently
    // classify all tool modules as escapes.
    let wat = r#"
        (module
          (memory (export "memory") 1)
          (func (export "evaluate") (param i32 i32) (result i32) (i32.const 0)))
    "#;
    let bytes = match wat::parse_str(wat) {
        Ok(bytes) => bytes,
        Err(err) => panic!("wat compile failed: {err}"),
    };
    let mut backend = match WasmtimeBackend::new() {
        Ok(backend) => backend,
        Err(err) => panic!("WasmtimeBackend::new failed: {err:?}"),
    };
    if let Err(err) = backend.load_module(&bytes, ESCAPE_FUEL_LIMIT) {
        panic!("benign module MUST load (over-rejecting); got {err:?}");
    }
    if let Err(err) = backend.evaluate(&minimal_request()) {
        panic!(
            "benign module MUST evaluate without error (over-rejecting); \
             got {err:?}"
        );
    }
}

#[test]
fn threat_tool_server_escape_kernel_mediation_blocks_tool_and_server_pivots() {
    // covers: tool_server_escape
    //
    // The connection deliberately accepts every invocation. Only the kernel's
    // capability mediation can prevent these pivots. A positive control first
    // proves the admitted path can run. Both pivots must then be denied without
    // incrementing either registered connection's invocation count.
    let mut kernel = escape_test_kernel();
    let admitted_invocations = Arc::new(AtomicUsize::new(0));
    let pivoted_invocations = Arc::new(AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(PermissiveEscapeServer {
        id: "admitted-server",
        invocations: Arc::clone(&admitted_invocations),
    }));
    kernel.register_tool_server(Box::new(PermissiveEscapeServer {
        id: "pivoted-server",
        invocations: Arc::clone(&pivoted_invocations),
    }));
    let subject = Keypair::from_seed(&[0x52; 32]);
    let capability = match kernel.issue_capability(&subject.public_key(), admitted_scope(), 300) {
        Ok(capability) => capability,
        Err(error) => panic!("issue mediation capability: {error}"),
    };

    let clock = FixedClock::new(current_unix_seconds());
    let guards: &[&dyn chio_kernel_core::Guard] = &[];
    let portable_admitted = kernel.evaluate_portable_verdict(
        &capability,
        &portable_escape_request(
            "tool-server-escape-portable-admitted",
            &capability,
            "admitted-server",
            "read_public",
        ),
        guards,
        &clock,
        None,
    );
    assert_eq!(portable_admitted.verdict, PortableVerdict::Allow);
    let portable_tool_pivot = kernel.evaluate_portable_verdict(
        &capability,
        &portable_escape_request(
            "tool-server-escape-portable-tool-pivot",
            &capability,
            "admitted-server",
            "exec_privileged",
        ),
        guards,
        &clock,
        None,
    );
    assert_eq!(portable_tool_pivot.verdict, PortableVerdict::Deny);
    let portable_server_pivot = kernel.evaluate_portable_verdict(
        &capability,
        &portable_escape_request(
            "tool-server-escape-portable-server-pivot",
            &capability,
            "pivoted-server",
            "read_public",
        ),
        guards,
        &clock,
        None,
    );
    assert_eq!(portable_server_pivot.verdict, PortableVerdict::Deny);

    let admitted = kernel.evaluate_tool_call_blocking(&escape_request(
        "tool-server-escape-admitted",
        &capability,
        "admitted-server",
        "read_public",
    ));
    let admitted = match admitted {
        Ok(response) => response,
        Err(error) => panic!("admitted control request must complete: {error}"),
    };
    assert_eq!(admitted.verdict, Verdict::Allow);
    assert_eq!(admitted_invocations.load(Ordering::SeqCst), 1);

    let tool_pivot = kernel.evaluate_tool_call_blocking(&escape_request(
        "tool-server-escape-tool-pivot",
        &capability,
        "admitted-server",
        "exec_privileged",
    ));
    let tool_pivot = match tool_pivot {
        Ok(response) => response,
        Err(error) => panic!("tool pivot must return a signed denial: {error}"),
    };
    assert_eq!(tool_pivot.verdict, Verdict::Deny);
    assert_eq!(admitted_invocations.load(Ordering::SeqCst), 1);

    let server_pivot = kernel.evaluate_tool_call_blocking(&escape_request(
        "tool-server-escape-server-pivot",
        &capability,
        "pivoted-server",
        "read_public",
    ));
    let server_pivot = match server_pivot {
        Ok(response) => response,
        Err(error) => panic!("server pivot must return a signed denial: {error}"),
    };
    assert_eq!(server_pivot.verdict, Verdict::Deny);
    assert_eq!(admitted_invocations.load(Ordering::SeqCst), 1);
    assert_eq!(pivoted_invocations.load(Ordering::SeqCst), 0);
}
