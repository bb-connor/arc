# Phase 278 Context

## Goal

Close the real input-driven error-handling gap that phase 277 uncovered:
external transport corruption should return explicit typed errors at the
framing boundary, and the stale roadmap wording should be corrected to match
ARC's actual canonical-JSON protocol.

## Audit Carry-Forward

Phase 277 found zero production literal `panic!` sites and zero production
`unwrap()` or `expect()` calls in `crates/arc-kernel/src/*` before any test
modules.

That means there are no live input-dependent literal panics to convert.
However, the transport layer still deserves one concrete hardening pass:

- `read_frame` maps EOF during the 4-byte header to `TransportError::ConnectionClosed`
- EOF during the body read currently bubbles out as a raw `std::io::Error`
  wrapped in `TransportError::Io`

For adversarial clients, a half-sent frame should be classified the same way as
any other mid-frame disconnect: structured connection-closed failure, not an
opaque raw I/O error.

## Code Surface

- `crates/arc-kernel/src/transport.rs` for framing and deserialization
- `.planning/ROADMAP.md` and `.planning/REQUIREMENTS.md` for milestone wording
  that still references JSON-RPC and live panic conversion work that the audit
  disproved

## Execution Direction

- make truncated frame bodies fail with `TransportError::ConnectionClosed`
- keep the fail-closed posture unchanged: malformed or incomplete input must be
  denied, never accepted
- repair milestone wording so phases 278-280 describe canonical JSON
  `AgentMessage` parsing rather than fictional JSON-RPC handling
