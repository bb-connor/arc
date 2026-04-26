// owned-by: M02 (fuzz lane); module authored under M02.P1.T3.b.
//
// Note on file layout: `crates/chio-a2a-adapter/src/lib.rs` assembles the
// crate via `include!()` of its sibling files (config, partner_policy,
// invoke, protocol, task_registry, mapping, discovery, auth, transport,
// tests). This file mirrors that pattern: `lib.rs` adds
// `#[cfg(feature = "fuzz")] include!("fuzz.rs");` so the contents below
// land at crate root. The fuzz API is namespaced under `pub mod fuzz`
// inside this file so callers see it as `chio_a2a_adapter::fuzz::*`,
// matching the `chio_mcp_edge::fuzz` precedent from M02.P1.T3.a.
//
// libFuzzer entry-point module for `chio-a2a-adapter`.
//
// Authored under M02.P1.T3.b (`.planning/trajectory/02-fuzzing-post-pr13.md`
// Phase 1, trust-boundary fuzz target #6). This module is gated behind
// the `fuzz` Cargo feature so it only compiles into the standalone
// `chio-fuzz` workspace at `../../fuzz`. The production build of
// `chio-a2a-adapter` never pulls in `arbitrary`, never exposes these
// symbols, and never gets recompiled with libFuzzer instrumentation.
//
// The single entry point [`fuzz::fuzz_a2a_envelope_decode`] is the
// canonical "SSE-decode -> per-envelope fan-out" trust-boundary pipeline
// for the A2A adapter:
//
// 1. **SSE-decode stage.** Bytes are interpreted as a UTF-8 Server-Sent
//    Events stream of the shape `event: <name>\ndata: <json>\n\n`. The
//    stream is fed through the private `parse_sse_stream` function in
//    `transport.rs` (the same parser the production
//    `get_sse` / `post_sse_json` paths in `auth.rs` consume). Because
//    `lib.rs` assembles the crate via `include!()`, the parser is in
//    scope at crate root and reachable from this module via `super::`
//    without any visibility change to the production surface.
// 2. **Per-envelope fan-out stage.** For every parsed event the per-event
//    JSON is forwarded through both production `decode_event` callbacks
//    in turn:
//    - The HTTP-JSON binding's identity passthrough (`Ok`).
//    - The JSON-RPC binding's `A2aJsonRpcResponse<Value>` unwrap (the
//      closure in `invoke_stream_jsonrpc` / `subscribe_task_jsonrpc`).
//    Each successful decode is also pushed through
//    `validate_stream_response` so the trust-boundary surface covers the
//    entire pipeline that production traffic crosses.
//
// The fan-out catches bugs that pure structural-parse fuzzing would
// miss: it exercises the SSE framer (line buffering, blank-line
// terminators, comment lines, partial frames), the per-envelope
// `serde_json::from_str` parser, the JSON-RPC envelope deserializer, and
// the stream-response validator on the same byte stream. All errors are
// silently consumed; the trust-boundary contract guarantees the only
// outcomes are an `Err` (good - fail-closed denial), an `Ok`
// (good - the pipeline ran every validation), or a panic / abort (which
// libFuzzer reports as a crash).
//
// No cross-iteration state is held: `parse_sse_stream` is invoked fresh
// on every call and the closures capture nothing. This matches the
// fail-closed contract: a malformed event on iteration N must not affect
// iteration N+1.

/// libFuzzer entry-point module for `chio-a2a-adapter`. Gated behind the
/// `fuzz` Cargo feature; see the file-level comment above for design
/// notes and the trust-boundary surface this module covers.
pub mod fuzz {
    use serde_json::Value;

    use super::{parse_sse_stream, validate_stream_response, A2aJsonRpcResponse, AdapterError};

    /// JSON-RPC `decode_event` closure used by `invoke_stream_jsonrpc` and
    /// `subscribe_task_jsonrpc` in `invoke.rs`. Reproduced verbatim here
    /// (modulo formatting) so the fuzz target exercises the same
    /// per-envelope unwrap path the production paths take. Kept as a
    /// free function (rather than imported from `invoke.rs`) because the
    /// production closure is anonymous and there is no public seam to
    /// import; reproducing it here pins the fuzz surface to the exact
    /// production behaviour while keeping the production side
    /// untouched.
    fn jsonrpc_decode_event(value: Value) -> Result<Value, AdapterError> {
        let response: A2aJsonRpcResponse<Value> = serde_json::from_value(value).map_err(|error| {
            AdapterError::Protocol(format!(
                "failed to decode A2A JSON-RPC stream event: {error}"
            ))
        })?;
        if response.jsonrpc != "2.0" {
            return Err(AdapterError::Protocol(format!(
                "unexpected JSON-RPC version {}",
                response.jsonrpc
            )));
        }
        if let Some(error) = response.error {
            return Err(AdapterError::Remote(format!(
                "A2A JSON-RPC error {}: {}",
                error.code, error.message
            )));
        }
        response.result.ok_or_else(|| {
            AdapterError::Protocol("A2A JSON-RPC stream event omitted `result`".to_string())
        })
    }

    /// HTTP-JSON-binding `decode_event` closure used by
    /// `invoke_stream_http_json` and `subscribe_task_http_json` in
    /// `invoke.rs`. The production code passes `Ok` directly; the wrapper
    /// here exists only to give the fan-out path a stable name and to
    /// keep `validate_stream_response` reachable on the resulting value.
    fn http_json_decode_event(value: Value) -> Result<Value, AdapterError> {
        Ok(value)
    }

    /// Drive arbitrary bytes through the SSE-decode + per-envelope fan-out
    /// trust-boundary pipeline.
    ///
    /// The byte stream is interpreted as a UTF-8 SSE stream and fed to
    /// `parse_sse_stream` twice, once per production `decode_event`
    /// closure (HTTP-JSON binding identity passthrough, JSON-RPC binding
    /// envelope unwrap). Every successfully decoded value is also handed
    /// to `validate_stream_response` independently of the
    /// `parse_sse_stream` call, so the validator is exercised even when
    /// the SSE framer rejects upstream framing. Errors and validator
    /// rejections are silently consumed: the trust-boundary contract is
    /// fail-closed by design.
    pub fn fuzz_a2a_envelope_decode(data: &[u8]) {
        // Fan-out 1: HTTP-JSON binding (identity decode_event).
        let _ = parse_sse_stream(data, http_json_decode_event);

        // Fan-out 2: JSON-RPC binding (envelope-unwrap decode_event).
        let _ = parse_sse_stream(data, jsonrpc_decode_event);

        // Fan-out 3: drive the validator independently. Split the bytes
        // into per-event `data:` lines using the same blank-line frame
        // separator the SSE parser uses, then for each frame run the
        // assembled JSON through both decode_event closures and the
        // validator. This keeps the validator reachable on inputs that
        // the SSE framer would otherwise short-circuit (e.g. event
        // payloads embedded in malformed frames where parse_sse_stream
        // returns Err early). Non-UTF-8 input is silently dropped here;
        // the SSE-stream fan-outs above already cover that surface.
        if let Ok(text) = std::str::from_utf8(data) {
            for frame in text.split("\n\n") {
                let mut data_lines: Vec<&str> = Vec::new();
                for line in frame.split('\n') {
                    let trimmed = line.trim_end_matches('\r');
                    if let Some(payload) = trimmed.strip_prefix("data:") {
                        data_lines.push(payload.trim_start());
                    }
                }
                if data_lines.is_empty() {
                    continue;
                }
                let payload = data_lines.join("\n");
                let value: Value = match serde_json::from_str(&payload) {
                    Ok(value) => value,
                    Err(_) => continue,
                };

                // Per-envelope: HTTP-JSON identity decode + validator.
                if let Ok(decoded) = http_json_decode_event(value.clone()) {
                    let _ = validate_stream_response(decoded);
                }

                // Per-envelope: JSON-RPC unwrap + validator on the
                // unwrapped `result` payload.
                if let Ok(decoded) = jsonrpc_decode_event(value) {
                    let _ = validate_stream_response(decoded);
                }
            }
        }
    }
}
