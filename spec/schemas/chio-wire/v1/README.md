# Chio Wire Schemas v1

These files are the machine-readable schema contract for the shipped native Chio
message families defined in [WIRE_PROTOCOL.md](../../../WIRE_PROTOCOL.md).

Directory layout:

- `agent/`
  - `tool_call_request.schema.json`
  - `list_capabilities.schema.json`
  - `heartbeat.schema.json`
- `kernel/`
  - `tool_call_chunk.schema.json`
  - `tool_call_response.schema.json`
  - `capability_list.schema.json`
  - `capability_revoked.schema.json`
  - `heartbeat.schema.json`
- `result/`
  - `ok.schema.json`
  - `stream_complete.schema.json`
  - `cancelled.schema.json`
  - `incomplete.schema.json`
  - `err.schema.json`
- `error/`
  - `capability_denied.schema.json`
  - `capability_expired.schema.json`
  - `capability_revoked.schema.json`
  - `policy_denied.schema.json`
  - `tool_server_error.schema.json`
  - `internal_error.schema.json`

Scope notes:

- These schemas cover the typed native Chio message families that the Rust
  implementation serializes directly today.
- The hosted MCP HTTP edge and trust-control APIs are specified normatively in
  `spec/WIRE_PROTOCOL.md`, but they are not represented as typed JSON Schema
  documents in this directory because the shipped implementation handles those
  payloads as protocol-specific HTTP / JSON-RPC values rather than dedicated
  Rust wire enums.
