// owned-by: M02 (fuzz lane); module authored under M02.P1.T3.c.
//
//! libFuzzer entry-point module for `chio-acp-edge`.
//!
//! Authored under M02.P1.T3.c (`.planning/trajectory/02-fuzzing-post-pr13.md`
//! Phase 1, trust-boundary fuzz target #7). This module is gated behind the
//! `fuzz` Cargo feature so it only compiles into the standalone `chio-fuzz`
//! workspace at `../../fuzz`. The production build of `chio-acp-edge` never
//! pulls in `arbitrary`, never exposes these symbols, and never gets
//! recompiled with libFuzzer instrumentation.
//!
//! The single entry point [`fuzz_acp_envelope_decode`] is the canonical
//! "decode -> handle_jsonrpc dispatch" trust-boundary pipeline for the ACP
//! edge:
//!
//! 1. **Decode stage.** Bytes are interpreted as a newline-delimited
//!    JSON-RPC stream (the same NDJSON envelope shape ACP transports use).
//!    Each non-empty trimmed line is fed to
//!    `serde_json::from_str::<serde_json::Value>` to produce a JSON-RPC
//!    envelope.
//! 2. **Dispatch stage.** Successfully decoded envelopes are forwarded to
//!    [`ChioAcpEdge::handle_jsonrpc`], the JSON-RPC method dispatcher that
//!    routes `session/list_capabilities`, `session/request_permission`,
//!    `tool/invoke`, `tool/stream`, `tool/cancel`, and `tool/resume` through
//!    the kernel-backed evaluator.
//!
//! The decode-then-dispatch combination is what catches bugs that pure
//! structural-parse fuzzing would miss: it exercises both the JSON parser
//! and the downstream method-dispatch state machine on the same byte
//! stream. Mirrors the T3.a precedent in `chio_mcp_edge::fuzz`.
//!
//! Fixture caching strategy: the kernel keypair, the agent keypair, and
//! the agent identifier are derived once via [`OnceLock`] from fixed
//! 32-byte seeds so the corpus surface is stable across libFuzzer runs.
//! The kernel itself, the [`ChioAcpEdge`], and the
//! [`AcpKernelExecutionContext`] are rebuilt fresh on every iteration:
//! [`ChioAcpEdge`] holds `Cell` / `RefCell` task state and is `!Sync`, so
//! it cannot live in a `OnceLock`; rebuilding per iteration also matches
//! the fail-closed contract that a malformed message on iteration N must
//! not bleed into iteration N+1. No upstream tool servers are registered;
//! the dispatcher is exercised against an empty capability set so every
//! `tool/invoke` short-circuits on `AcpEdgeError::ToolNotFound` before the
//! kernel does any signed work, every `session/request_permission`
//! short-circuits on a missing `capability_bindings` entry, and the
//! remaining session / tool methods reach their JSON-RPC error paths or
//! their notification-ack paths.
//!
//! Fail-closed contract: every parse error and every dispatcher-error
//! response is silently consumed. The trust-boundary surface guarantees
//! the only outcomes are an `Err`-shaped JSON-RPC response (good), an
//! `Ok`-shaped JSON-RPC response (also good - the dispatcher ran every
//! validation), or a panic / abort (which libFuzzer reports as a crash).

use std::sync::OnceLock;

use chio_core::capability::{
    CapabilityToken, CapabilityTokenBody, ChioScope, Operation, ToolGrant,
};
use chio_core::crypto::Keypair;
use chio_kernel::{ChioKernel, KernelConfig, DEFAULT_CHECKPOINT_BATCH_SIZE};

use crate::{AcpEdgeConfig, AcpKernelExecutionContext, ChioAcpEdge};

/// Deterministic 32-byte seed for the fuzz-only kernel keypair. Fixed so the
/// corpus surface is stable across libFuzzer runs.
const FUZZ_KERNEL_SEED: [u8; 32] = [
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80,
];

/// Deterministic 32-byte seed for the fuzz-only agent keypair.
const FUZZ_AGENT_SEED: [u8; 32] = [
    0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90,
    0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0,
];

/// Cached agent identifier (hex-encoded public key) for the fuzz fixture.
/// Built once per process so successive iterations see a stable identifier.
fn agent_id() -> &'static str {
    static AGENT_ID: OnceLock<String> = OnceLock::new();
    AGENT_ID
        .get_or_init(|| Keypair::from_seed(&FUZZ_AGENT_SEED).public_key().to_hex())
        .as_str()
}

/// Build a fresh [`ChioKernel`] for one fuzz iteration. The kernel is
/// rebuilt rather than cached because each iteration also rebuilds a
/// fresh [`ChioAcpEdge`] (which is `!Sync` due to `Cell` / `RefCell`
/// task state); pairing the two keeps the per-iteration fixture
/// self-contained.
fn make_kernel() -> ChioKernel {
    let keypair = Keypair::from_seed(&FUZZ_KERNEL_SEED);
    let config = KernelConfig {
        ca_public_keys: vec![keypair.public_key()],
        keypair,
        max_delegation_depth: 5,
        policy_hash: "fuzz-policy".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    };
    ChioKernel::new(config)
}

/// Build a fresh [`ChioAcpEdge`] fixture for one fuzz iteration.
///
/// Returns `None` if the constructor surfaces an `AcpEdgeError`. The
/// constructor is expected to succeed for the empty-manifest case used
/// here, but we propagate `Option` rather than `unwrap` / `expect` so the
/// crate's `unwrap_used = "deny"` lint stays satisfied.
fn make_edge() -> Option<ChioAcpEdge> {
    // Empty manifest set: the dispatcher is the trust-boundary surface
    // we want to exercise. With no capabilities registered, every
    // `tool/invoke` returns `AcpEdgeError::ToolNotFound`, every
    // `session/request_permission` denies on missing binding, and the
    // session / tool / streaming methods reach their well-defined
    // JSON-RPC error or notification-ack paths.
    ChioAcpEdge::new(AcpEdgeConfig::default(), vec![]).ok()
}

/// Build a per-iteration [`AcpKernelExecutionContext`] with a freshly
/// signed capability token bound to the fuzz issuer / subject pair. The
/// capability is well-formed but does not match any registered tool
/// (there are none), so it cannot grant access; it exists so the
/// dispatcher's permission-evaluation paths see a structurally valid
/// token rather than short-circuiting on a deserialization failure
/// upstream of the trust-boundary surface we care about.
///
/// Returns `None` if `CapabilityToken::sign` fails. Signing can fail in
/// principle (Ed25519 signing on a corrupt key); propagating `Option`
/// keeps the crate's `unwrap_used = "deny"` lint satisfied.
fn make_execution() -> Option<AcpKernelExecutionContext> {
    let issuer = Keypair::from_seed(&FUZZ_KERNEL_SEED);
    let subject = Keypair::from_seed(&FUZZ_AGENT_SEED);
    // Fixed timestamps so the capability is always valid for the duration
    // of the iteration. Avoids touching the system clock from inside the
    // fuzz loop.
    let issued_at: u64 = 1_700_000_000;
    let expires_at: u64 = issued_at + 3600;
    let body = CapabilityTokenBody {
        id: "fuzz-acp-cap".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: ChioScope {
            grants: vec![ToolGrant {
                server_id: "fuzz-srv".to_string(),
                tool_name: "fuzz-tool".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: vec![],
            prompt_grants: vec![],
        },
        issued_at,
        expires_at,
        delegation_chain: vec![],
    };
    let capability: CapabilityToken = CapabilityToken::sign(body, &issuer).ok()?;
    Some(AcpKernelExecutionContext {
        capability,
        agent_id: agent_id().to_string(),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
    })
}

/// Drive arbitrary bytes through the decode-then-handle_jsonrpc
/// trust-boundary pipeline.
///
/// Bytes are interpreted as a newline-delimited JSON-RPC stream. Every
/// non-empty trimmed line is parsed with `serde_json::from_str` and, on
/// success, forwarded to [`ChioAcpEdge::handle_jsonrpc`] against a fresh
/// per-iteration kernel + edge + execution-context fixture. Errors and
/// JSON-RPC error responses are silently consumed: the trust-boundary
/// contract guarantees the only outcomes are an `Err`-shaped JSON-RPC
/// response (good), an `Ok`-shaped JSON-RPC response (also good - the
/// edge ran the full dispatcher path), or a panic / abort (which
/// libFuzzer reports as a crash). No arbitrary byte stream can produce a
/// meaningful successful invocation because the agent has no
/// capabilities and no tool manifests are registered, so every
/// dispatched request hits an authorisation / not-found edge.
///
/// The fixture is rebuilt fresh on every iteration so libFuzzer-injected
/// sequences cannot poison cross-iteration kernel, edge, or session
/// state. This matches the fail-closed contract: a malformed message on
/// iteration N must not affect iteration N+1.
pub fn fuzz_acp_envelope_decode(data: &[u8]) {
    use std::io::BufRead;

    let kernel = make_kernel();
    let edge = match make_edge() {
        Some(edge) => edge,
        None => return,
    };
    let execution = match make_execution() {
        Some(execution) => execution,
        None => return,
    };

    let mut reader = std::io::BufReader::new(data);
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => return,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let Ok(message) = serde_json::from_str::<serde_json::Value>(trimmed) else {
                    continue;
                };
                let _ = edge.handle_jsonrpc(message, &kernel, &execution);
            }
            Err(_) => return,
        }
    }
}
