# Summary 180-01

Phase `180-01` split the four target runtime shells along real ownership
seams:

- `remote_mcp.rs` now delegates admin routing and admin-only helpers to
  `remote_mcp/admin.rs`
- `trust_control.rs` now delegates health composition to
  `trust_control/health.rs`
- `arc-mcp-edge/src/runtime.rs` now delegates protocol glue to
  `runtime/protocol.rs`
- `arc-kernel/src/lib.rs` now delegates receipt support and request matching
  to `receipt_support.rs` and `request_matching.rs`
