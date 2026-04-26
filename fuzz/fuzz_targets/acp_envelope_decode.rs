// owned-by: M02 (fuzz lane); target authored under M02.P1.T3.c.
//
//! libFuzzer harness for the `chio-acp-edge` decode-then-handle_jsonrpc
//! trust boundary.
//!
//! The ACP envelope surface is fail-closed by construction: the edge runtime
//! parses every newline-terminated JSON-RPC envelope into a
//! `serde_json::Value`, and routes requests through
//! `ChioAcpEdge::handle_jsonrpc`, which surfaces protocol violations as
//! JSON-RPC error responses (`-32601 method not found`, `-32603 internal
//! error`, etc) rather than a panic, abort, or `Ok(_)` that would let a
//! malformed message escape into the rest of the system. This target
//! exists to catch parse-path regressions (unwrap/expect/UB) and
//! dispatch-state-machine bugs in:
//!
//! - The newline-delimited JSON-RPC line framing the ACP transport
//!   layer consumes.
//! - The top-level `serde_json::Value` envelope deserializer.
//! - `ChioAcpEdge::handle_jsonrpc` (the JSON-RPC method dispatcher routing
//!   `session/list_capabilities`, `session/request_permission`,
//!   `tool/invoke`, `tool/stream`, `tool/cancel`, and `tool/resume`
//!   through the kernel-backed evaluator).
//!
//! Input layout: bytes are forwarded to the edge-side fuzz entry point
//! `chio_acp_edge::fuzz::fuzz_acp_envelope_decode`, which interprets them
//! as a newline-delimited JSON-RPC stream and runs every decoded envelope
//! through the dispatcher against a fresh per-iteration kernel + edge +
//! execution-context fixture. The seed corpus under
//! `corpus/acp_envelope_decode/` mixes empty input, deterministic 64-byte
//! garbage, ACP `session/list_capabilities` /
//! `session/request_permission` / `tool/invoke` envelopes, a truncated
//! envelope, and an oversize-method envelope so libFuzzer has a head
//! start on every parse plus dispatch path.

#![no_main]

use chio_acp_edge::fuzz::fuzz_acp_envelope_decode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_acp_envelope_decode(data);
});
