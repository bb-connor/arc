---
phase: 311-wire-protocol-specification
created: 2026-04-13
status: complete
---

# Phase 311 Research

## Primary Code Sources

- `crates/arc-core-types/src/message.rs`
- `crates/arc-kernel/src/transport.rs`
- `crates/arc-core-types/src/session.rs`
- `crates/arc-mcp-edge/src/runtime/runtime_tests.rs`
- `crates/arc-cli/src/remote_mcp/http_service.rs`
- `crates/arc-cli/src/remote_mcp/session_core.rs`
- `crates/arc-cli/src/trust_control/service_types.rs`
- `crates/arc-cli/src/trust_control/http_handlers_a.rs`

## Existing Documentation

- `spec/PROTOCOL.md`
- `docs/adr/ADR-0001-edge-protocol-shape.md`
- `docs/research/01-current-state.md`
- `tests/conformance/README.md`

## Findings

### Native ARC framed transport

- The framing contract is already concrete and small:
  - 4-byte big-endian unsigned length prefix
  - canonical JSON payload bytes
  - hard maximum message size `16 * 1024 * 1024`
- EOF while reading either the prefix or payload maps to
  `TransportError::ConnectionClosed`.
- Oversized frames fail before payload read with
  `TransportError::MessageTooLarge`.
- There is no native handshake message today. The framed lane begins directly
  with `AgentMessage`.

### Native message catalog

- Agent-to-kernel:
  - `tool_call_request`
  - `list_capabilities`
  - `heartbeat`
- Kernel-to-agent:
  - `tool_call_chunk`
  - `tool_call_response`
  - `capability_list`
  - `capability_revoked`
  - `heartbeat`
- Nested tool-call terminal families:
  - `ok`
  - `stream_complete`
  - `cancelled`
  - `incomplete`
  - `err`
- Nested error codes:
  - `capability_denied`
  - `capability_expired`
  - `capability_revoked`
  - `policy_denied`
  - `tool_server_error`
  - `internal_error`

### Hosted MCP edge

- `arc mcp serve-http` exposes `POST /mcp`, `GET /mcp`, and `DELETE /mcp`.
- `initialize` is a JSON-RPC request sent to `POST /mcp` without an
  `MCP-Session-Id` header.
- Successful initialize returns an SSE response and sets `MCP-Session-Id`.
- Follow-up POST and GET traffic requires `MCP-Session-Id`; GET is the
  notification stream.
- Notification replay uses `Last-Event-ID` in the format
  `{session_id}-{sequence}`.
- Terminal hosted-session states require re-initialization rather than silent
  reuse.

### Trust-control capability lifecycle

- Capability issuance: `POST /v1/capabilities/issue`
- Federated/delegated issuance:
  `POST /v1/federation/capabilities/issue`
- Revocation: `POST /v1/revocations`
- Receipt lookup: `GET /v1/receipts/query`
- The federated issuance path optionally binds a signed delegation policy and
  an `upstreamCapabilityId` to anchor multi-hop lineage.

## Implications For The Spec

- The normative document must explicitly separate native framing from hosted
  initialization and trust-control issuance.
- Sequence diagrams should cover the full shipped lifecycle by composing those
  three surfaces rather than expanding the native message family beyond what
  the code actually serializes.
- The JSON Schemas should be versioned and limited to the typed native message
  families, because those are the only wire messages with direct Rust
  serialization contracts in the current implementation.
