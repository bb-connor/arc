status: passed

# Phase 27 Verification

## Result

Phase 27 passed. The MCP edge runtime now lives in a dedicated
`arc-mcp-edge` crate, `arc-mcp-adapter` is reduced to translation plus
transport adaptation with compatibility reexports, and `arc-a2a-adapter`
no longer concentrates its behavior in one monolithic source file.

## Evidence

- `cargo check -p arc-mcp-edge -p arc-mcp-adapter -p arc-a2a-adapter`
- `cargo test -p arc-mcp-edge -- --nocapture`
- `cargo test -p arc-a2a-adapter -- --nocapture`
- `cargo test -p arc-cli --test mcp_serve_http -- --nocapture --test-threads=1`
- `wc -l crates/arc-mcp-adapter/src/lib.rs crates/arc-mcp-edge/src/lib.rs crates/arc-mcp-edge/src/runtime.rs crates/arc-a2a-adapter/src/lib.rs crates/arc-a2a-adapter/src/*.rs | sort -nr | head -n 15`

## Notes

- `crates/arc-mcp-edge/src/runtime.rs` is still large, but it is now isolated
  behind its own crate boundary instead of being embedded inside
  `arc-mcp-adapter`
- the A2A split intentionally preserved the original root-module item layout to
  minimize API churn during this milestone
