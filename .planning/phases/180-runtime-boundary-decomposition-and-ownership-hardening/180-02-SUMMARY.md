# Summary 180-02

Phase `180-02` added a source-shape regression guard in
`crates/arc-control-plane/tests/runtime_boundaries.rs`.

That guard checks:

- `arc-cli` still re-exports `arc-hosted-mcp` instead of inlining hosted MCP
  runtime code
- `arc-control-plane` and `arc-hosted-mcp` remain the owners of
  `trust_control.rs` and `remote_mcp.rs`
- the extracted support files exist
- the major runtime shells stay below the phase-180 line-count ceilings
