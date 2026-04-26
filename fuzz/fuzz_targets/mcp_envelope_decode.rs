// owned-by: M02 (fuzz lane); target authored under M02.P1.T3.a.
//
//! libFuzzer harness for the `chio-mcp-edge` decode-then-evaluator-dispatch
//! trust boundary.
//!
//! The MCP envelope surface is fail-closed by construction: the edge runtime
//! parses every newline-terminated JSON-RPC envelope into a
//! `serde_json::Value`, validates the `jsonrpc` discriminator, then routes
//! requests through `ChioMcpEdge::handle_jsonrpc`, which surfaces protocol
//! violations as JSON-RPC error responses (`-32600 invalid jsonrpc envelope`,
//! `-32601 method not found`, `-32602 invalid params`, `-32603 internal
//! error`, `-32002 server not initialized`, etc) rather than a panic, abort,
//! or `Ok(_)` that would let a malformed message escape into the rest of
//! the system. This target exists to catch parse-path regressions
//! (unwrap/expect/UB) and dispatch-state-machine bugs in:
//!
//! - The newline-delimited JSON-RPC line framing inherited from
//!   `chio_mcp_adapter::transport::StdioMcpTransport`.
//! - The top-level `serde_json::Value` envelope deserializer.
//! - `ChioMcpEdge::handle_jsonrpc` (the JSON-RPC method dispatcher routing
//!   `initialize`, `tools/list`, `tools/call`, `resources/list`,
//!   `resources/read`, `prompts/list`, `prompts/get`, `completion/complete`,
//!   `tasks/*`, `notifications/*`, and the rest of the MCP method
//!   namespace through the kernel-backed evaluator).
//!
//! Input layout: bytes are forwarded to the edge-side fuzz entry point
//! `chio_mcp_edge::fuzz::fuzz_mcp_envelope_decode`, which interprets them
//! as a newline-delimited JSON-RPC stream and runs every decoded envelope
//! through the dispatcher against a fresh per-iteration kernel + edge
//! fixture. The seed corpus under `corpus/mcp_envelope_decode/` mixes empty
//! input, deterministic 64-byte garbage, MCP `initialize` / `tools/list` /
//! `tools/call` envelopes, a truncated envelope, and an oversize-method
//! envelope so libFuzzer has a head start on every parse plus dispatch
//! path.

#![no_main]

use chio_fuzz::canonical_json::canonical_json_mutate;
use chio_mcp_edge::fuzz::fuzz_mcp_envelope_decode;
use libfuzzer_sys::{fuzz_mutator, fuzz_target};

fuzz_target!(|data: &[u8]| {
    fuzz_mcp_envelope_decode(data);
});

// M02.P2.T6: opt this canonical-JSON-decoding target into the
// structure-aware mutator at `fuzz/mutators/canonical_json.rs`. The
// fuzz_target body is unchanged from M02.P1.T3.a; only the per-iteration
// mutation strategy switches from libFuzzer's default random-byte
// mutator to the parse / mutate / re-canonicalize pipeline that keeps
// inputs shape-valid past the JSON parse stage.
fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    canonical_json_mutate(data, size, max_size, seed)
});
