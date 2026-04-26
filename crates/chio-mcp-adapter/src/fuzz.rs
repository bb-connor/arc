// owned-by: M02 (fuzz lane); module authored under M02.P1.T3.a.
//
//! libFuzzer entry-point module for `chio-mcp-adapter`.
//!
//! Authored under M02.P1.T3.a (`.planning/trajectory/02-fuzzing-post-pr13.md`
//! Phase 1, trust-boundary fuzz target #5). This module is gated behind the
//! `fuzz` Cargo feature so it only compiles into the standalone `chio-fuzz`
//! workspace at `../../fuzz`. The production build of `chio-mcp-adapter`
//! never pulls in `arbitrary`, never exposes these symbols, and never gets
//! recompiled with libFuzzer instrumentation.
//!
//! The single entry point [`fuzz_mcp_envelope_parse`] drives arbitrary bytes
//! through the adapter's MCP envelope parse path. MCP uses newline-delimited
//! JSON-RPC over stdin/stdout (see
//! `crates/chio-mcp-adapter/src/transport.rs::read_line`), so the parse
//! contract is two-stage: split the byte stream into newline-terminated
//! lines, then `serde_json::from_str` each non-empty line into a
//! `serde_json::Value` envelope. Both stages are reachable from arbitrary
//! bytes; both must surface bad inputs as errors rather than panics.
//!
//! Companion entry point: the edge crate's
//! `chio_mcp_edge::fuzz::fuzz_mcp_envelope_decode` carries the full
//! decode-then-evaluator-dispatch pipeline. This adapter-side wrapper is
//! retained as a smaller seam so future tickets that target only the
//! transport-side parse path can reuse it without standing up the full edge
//! kernel fixture.

use std::io::BufRead;

/// Drive arbitrary bytes through the adapter's MCP envelope parse path.
///
/// Bytes are interpreted as a newline-delimited JSON-RPC stream, mirroring
/// what `chio_mcp_adapter::transport::StdioMcpTransport`'s reader thread
/// receives from an upstream MCP subprocess. The wrapper:
///
/// 1. Wraps the byte slice in a `BufRead` and iterates `read_line` to mirror
///    the per-line framing used by the real transport (the production code
///    calls `BufRead::read_line` on each upstream message in turn, so any
///    panic in `std::io`'s newline handling against arbitrary bytes would
///    surface here).
/// 2. Trims each line and feeds the trimmed contents to
///    `serde_json::from_str::<serde_json::Value>` exactly as
///    `transport::read_line` does. Empty trimmed lines are skipped to match
///    the real loop's behaviour on blank framing bytes.
///
/// Errors at every step are silently consumed: the trust-boundary contract
/// guarantees the only outcomes are `Err(serde_json::Error)` (good),
/// successful `Ok(Value)` (also good - the adapter forwards on to the
/// downstream evaluator), or a panic / abort (which libFuzzer reports as a
/// crash). The returned `Value` is intentionally discarded; this entry point
/// is the seam reviewers can reuse if a future ticket wants pure
/// transport-side fuzzing without the kernel fixture cost.
pub fn fuzz_mcp_envelope_parse(data: &[u8]) {
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
                let _ = serde_json::from_str::<serde_json::Value>(trimmed);
            }
            Err(_) => return,
        }
    }
}
