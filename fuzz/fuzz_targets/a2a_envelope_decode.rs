// owned-by: M02 (fuzz lane); target authored under M02.P1.T3.b.
//
//! libFuzzer harness for the `chio-a2a-adapter` SSE-decode + per-envelope
//! fan-out trust boundary.
//!
//! The A2A adapter ingests Server-Sent Events (SSE) streams from remote
//! agent endpoints (the `text/event-stream` responses behind
//! `SendStreamingMessage` / `SubscribeToTask` and the corresponding
//! HTTP-JSON binding paths). Production traffic flows through
//! `parse_sse_stream` (the line-buffered SSE framer in
//! `chio_a2a_adapter::transport`) and then a per-event `decode_event`
//! closure that either passes the JSON through as-is (HTTP-JSON binding)
//! or unwraps it as an `A2aJsonRpcResponse<Value>` (JSON-RPC binding).
//! Every successfully decoded value is then handed to
//! `validate_stream_response`, which enforces the
//! `task` / `message` / `statusUpdate` / `artifactUpdate` discriminator
//! and detects terminal task states.
//!
//! This target exists to catch parse-path regressions
//! (unwrap/expect/UB) and validator-state-machine bugs in:
//!
//! - The SSE line framer and blank-line frame separator inherited from
//!   `chio_a2a_adapter::transport::parse_sse_stream`.
//! - The per-event `serde_json::from_str::<Value>` decoder.
//! - The JSON-RPC envelope deserializer
//!   (`A2aJsonRpcResponse<Value>` parse + `result` / `error` arbitration).
//! - The stream-response validator
//!   (`task` / `message` / `statusUpdate` / `artifactUpdate` exclusivity
//!   plus the per-arm field validators).
//!
//! Input layout: bytes are forwarded to the adapter-side fuzz entry point
//! `chio_a2a_adapter::fuzz::fuzz_a2a_envelope_decode`, which interprets
//! them as a UTF-8 SSE stream and runs every parsed event through both
//! production `decode_event` closures plus the validator. The seed
//! corpus under `corpus/a2a_envelope_decode/` mixes empty input,
//! deterministic 64-byte garbage, a minimal SSE event, two back-to-back
//! events (the per-envelope fan-out path), an event with an invalid
//! event name, a truncated frame, and an oversize `data:` payload so
//! libFuzzer has a head start on every parse plus validate path.

#![no_main]

use chio_a2a_adapter::fuzz::fuzz_a2a_envelope_decode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_a2a_envelope_decode(data);
});
