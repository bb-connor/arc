---
phase: 307-identity-resolution-and-scaffolding
created: 2026-04-13
status: complete
---

# Phase 307 Research

## Findings

- The literal rename gate only matched seven files under
  `README.md`, `docs/`, and `crates/*/src/*.rs`; no Rust source files still
  contained `CHIO`, so the cleanup could stay narrow.
- `examples/docker/mock_mcp_server.py` and `examples/docker/smoke_client.py`
  already demonstrated the minimal MCP initialize -> list -> tool-call flow
  needed for onboarding.
- `crates/arc-cli/tests/mcp_serve.rs` confirmed that the wrapped MCP stdio path
  can be driven with simple newline-delimited JSON-RPC messages for the current
  local test surface.

## Consequences

- The scaffold could avoid unpublished ARC library dependencies by generating a
  normal Cargo project that only depends on `serde_json`.
- The generated demo should shell out to `arc mcp serve` and a nested
  `cargo run --bin hello_server`, then verify the recorded receipt with
  `arc receipt list`.
- The rename cleanup could be handled as a targeted documentation pass rather
  than a risky tree-wide refactor.
