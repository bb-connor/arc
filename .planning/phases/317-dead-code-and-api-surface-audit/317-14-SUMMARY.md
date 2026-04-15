# Summary 317-14

Phase `317` then took the `arc-mcp-edge` runtime/protocol helper cleanup wave.

The implemented refactor updated:

- `crates/arc-mcp-edge/src/runtime.rs`
- `crates/arc-mcp-edge/src/runtime/protocol.rs`

Verification that passed during this wave:

- `cargo fmt -p arc-mcp-edge`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave14 cargo check -p arc-mcp-edge`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave14 cargo test -p arc-mcp-edge --lib`
- `rg -n '#\[allow\(clippy::too_many_arguments\)\]' crates --glob '!**/tests/**' | wc -l`
- `git diff --check -- crates/arc-mcp-edge/src/runtime.rs crates/arc-mcp-edge/src/runtime/protocol.rs`

This wave removed five non-test `#[allow(clippy::too_many_arguments)]` sites:

- `jsonrpc_protocol_error`
- `evaluate_tool_call_operation_with_transport`
- `evaluate_tool_call_operation_with_transport_channel`
- `tool_result_for_kernel_response`
- `kernel_response_to_tool_result`

Those internal runtime helpers now pass typed request/result context structs
instead of repeating long parameter lists across the edge/runtime boundary.

Current inventory after this wave:

- non-test `#[allow(clippy::too_many_arguments)]` sites still present across the
  workspace: `13`
- remaining highest concentration: `crates/arc-cli/src/trust_control/credit_and_loss.rs`
  (`2`)
