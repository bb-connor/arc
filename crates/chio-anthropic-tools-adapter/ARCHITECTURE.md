# chio-anthropic-tools-adapter Architecture Notes

## Boundary

`chio-anthropic-tools-adapter` owns mediation for Anthropic Messages
`tool_use` traffic. It translates Anthropic batch and streaming payloads into
`chio-tool-call-fabric` invocations, applies the manifest-backed server-tool
gate, and lowers Chio verdicts back into Anthropic `tool_result` blocks.

The crate does not own kernel dispatch, manifest schema validation, generic
HTTP transport classification, or provider-fixture replay. Those remain in
`chio-kernel`, `chio-manifest`, `chio-provider-adapter-core`, and
`chio-provider-conformance`.

## Module Boundaries

- `lib.rs` is the public facade, adapter configuration, transport entrypoint,
  and provider identity surface.
- `adapter.rs` owns non-streaming `messages.create` lift and lower behavior.
- `streaming.rs` owns Anthropic event-stream gating and the fail-closed
  buffer-until-verdict state machine.
- `native.rs` owns Anthropic wire content-block structs and the optional
  `computer-use` server-tool catalog.
- `manifest.rs` owns the server-tool allowlist derived from
  `chio-manifest`.
- `transport.rs` pins Anthropic headers, endpoint constants, and test
  transport construction while delegating HTTP mechanics to
  `chio-provider-adapter-core`.

## Pain Points

The streaming module still carries a local SSE parser even though the shared
provider adapter core owns the cross-provider SSE parser. The local parser
reconstructs forwarded frame bytes with normalized newline delimiters, so an
allowed CRLF Anthropic event stream is released with LF bytes. That is avoidable
byte drift at the mediation boundary.

## Security And API Constraints

- Streaming tool-use frames must remain buffered until `content_block_stop`
  and a Chio verdict allows the invocation.
- Deny verdicts, evaluator errors, malformed frame order, malformed input JSON,
  and unsupported server-tool gates must fail closed before releasing buffered
  tool-use bytes.
- Allowed SSE frames should be forwarded byte-for-byte. The gate may inspect
  frame structure, but it should not rewrite provider bytes as a side effect of
  parsing.
- Server tools remain gated by both the `computer-use` feature and manifest
  `server_tools`; custom client-hosted tools must not be forced through the
  server-tool allowlist.

## Affected Dependents

`chio-provider-conformance` replays Anthropic fixtures through this adapter
when built with `fixtures-anthropic`. The intended change is internal to SSE
parsing and should preserve public APIs and fixture semantics. If dependent
replay fails, the parser contract should be corrected here rather than patched
in replay code.

## Planned Improvement

Move Anthropic streaming onto the shared
`chio-provider-adapter-core::parse_sse_frames` parser while keeping the
Anthropic-specific event/data cross-check. Add a regression proving allowed
CRLF event-stream bytes are forwarded unchanged.
