---
phase: 27
slug: adapter-decomposition
status: complete
created: 2026-03-25
---

# Phase 27 Research

## Findings

1. `pact-mcp-adapter/src/edge.rs` is only referenced through the crate's public
   reexports, which makes a compatibility facade straightforward.
2. The MCP edge runtime does not depend on the adapter's translation logic; it
   only needs the shared transport trait and error/result types.
3. `pact-mcp-adapter/src/transport.rs` and the adapter wrapper code can keep
   using `crate::{AdapterError, McpTransport, ...}` if those names become
   reexports from `pact-mcp-edge`.
4. The A2A adapter already clusters into stable concern regions by line range:
   config/partner policy, invocation, protocol models, task registry, mapping,
   discovery, auth, transport, and tests.
5. A root-facade split is the lowest-risk first pass for `pact-a2a-adapter`
   because it preserves privacy and avoids widespread signature churn.

## Decision

Phase 27 will use this shape:

- `pact-mcp-edge`
  - owns `AdapterError`, `McpTransport`, shared MCP transport/result types, and
    `PactMcpEdge`
  - becomes the real home of the MCP edge runtime tests
- `pact-mcp-adapter`
  - keeps manifest translation, wrapped-server adapters, native service
    helpers, and concrete transport adapters
  - reexports the MCP edge types for compatibility
- `pact-a2a-adapter`
  - keeps the same crate surface but is split across concern files:
    `config.rs`, `partner_policy.rs`, `invoke.rs`, `protocol.rs`,
    `task_registry.rs`, `mapping.rs`, `discovery.rs`, `auth.rs`,
    `transport.rs`, and `tests.rs`

## Verification Inputs

- `wc -l crates/pact-mcp-adapter/src/edge.rs crates/pact-a2a-adapter/src/lib.rs`
- `rg -n "pub mod edge|pub use edge|crate::edge|PactMcpEdge|McpEdgeConfig" crates`
- `rg -n "A2aAdapter|A2aAdapterConfig|A2aPartnerPolicy" crates/pact-a2a-adapter/src/lib.rs`
