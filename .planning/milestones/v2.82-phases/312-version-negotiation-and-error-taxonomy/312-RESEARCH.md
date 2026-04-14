---
phase: 312-version-negotiation-and-error-taxonomy
created: 2026-04-13
status: complete
---

# Phase 312 Research

## Primary Code Sources

- `crates/arc-mcp-edge/src/runtime.rs`
- `crates/arc-mcp-edge/src/runtime/runtime_tests.rs`
- `crates/arc-mcp-edge/src/runtime/protocol.rs`
- `crates/arc-cli/src/remote_mcp/http_service.rs`
- `crates/arc-cli/src/remote_mcp/oauth.rs`
- `crates/arc-cli/src/trust_control/underwriting_and_support.rs`
- `crates/arc-core-types/src/message.rs`
- `docs/BINDINGS_API.md`

## Findings

### Version surfaces

- Hosted MCP currently advertises one protocol version:
  `2025-11-25` (`MCP_PROTOCOL_VERSION` in `arc-mcp-edge/src/runtime.rs`).
- The hosted edge stores the selected session protocol version after a
  successful initialize response and later validates the
  `MCP-Protocol-Version` request header against that stored value.
- The hosted runtime does not currently inspect
  `initialize.params.protocolVersion`; it always returns the server constant.

### Error surfaces

- Native ARC `ToolCallError` already has stable snake_case identifiers but not
  numeric registry codes.
- Hosted MCP runtime already carries numeric JSON-RPC codes and can emit
  structured `error.data` via `jsonrpc_error_with_data`.
- Trust-control already returns JSON for plain HTTP errors, but only as a
  string payload under `error`.
- Bindings documentation already establishes the precedent that ARC can publish
  a stable, machine-readable error taxonomy outside the runtime internals.

## Implications

- The smallest truthful negotiation change is exact-match validation of
  `initialize.params.protocolVersion` against the hosted server's supported
  versions.
- The machine-readable taxonomy should be a checked-in registry artifact rather
  than an enum hardcoded into one crate only.
- Hosted JSON-RPC initialize rejection is the best low-risk place to attach the
  new numeric ARC protocol error descriptor immediately.
