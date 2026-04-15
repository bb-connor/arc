# Phase 287 Context

## Goal

Ship ARC as a minimal container image and provide a Compose-ready example that
wraps an MCP server behind `arc mcp serve-http`.

## Constraints

- `arc mcp serve-http` wraps a subprocess command directly; it does not proxy
  to a separate upstream URL.
- The Compose example therefore needs a container image that includes both the
  `arc` binary and a small wrapped MCP server process.
- The repo had no existing `Dockerfile`, `.dockerignore`, or Compose example.

## Findings

- `crates/arc-cli/src/main.rs` already exposes the exact operator surface
  needed for packaging: `arc mcp serve-http --policy --server-id --listen
  <command>...`.
- The workspace already uses `rusqlite` with the `bundled` feature and
  `reqwest` with `rustls-tls`, which keeps Alpine packaging tractable.
- A tiny example-owned Python MCP server is sufficient for the Compose path and
  avoids coupling the developer example to the full conformance harness.

## Implementation Direction

- Add a multi-stage repo-root `Dockerfile`.
- Publish two runtime targets:
  - `arc`: minimal CLI image
  - `arc-mcp-demo`: CLI image plus a tiny Python MCP server and demo policy
- Add `examples/docker/` with Compose, policy, smoke client, and README.
