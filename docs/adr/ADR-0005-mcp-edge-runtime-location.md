# ADR-0005: MCP Edge Runtime Location

- Status: Proposed
- Decision owner: protocol and interop lanes
- Related plan item: `D5` in [../EXECUTION_PLAN.md](../EXECUTION_PLAN.md)

## Context

The repository already contains `arc-mcp-adapter`, which wraps MCP servers for use under ARC.

As ARC grows an MCP-compatible public edge, there are two choices:

1. keep extending `arc-mcp-adapter` until it becomes the MCP edge runtime
2. keep `arc-mcp-adapter` focused on migration and create a separate MCP edge runtime

## Decision

ARC will keep `arc-mcp-adapter` focused on migration and adaptation of upstream MCP servers.

ARC will add a separate MCP edge runtime module or crate for first-class MCP-compatible hosting.

## Rationale

These are different responsibilities:

- the adapter translates and wraps foreign MCP servers
- the edge runtime hosts ARC itself as an MCP-compatible endpoint

Merging them would blur concerns and make both paths harder to reason about.

## Consequences

### Positive

- clearer ownership boundaries
- easier testing of hosted edge behavior versus wrapped-server behavior
- more maintainable long-term architecture

### Negative

- one more module or crate to maintain
- some duplicated MCP-shaped types may need careful factoring

## Required follow-up

- define which MCP-shaped types live in shared core/edge compatibility code
- keep adapter tests distinct from edge-runtime tests
- document when to use the adapter versus the hosted edge

## Guideline

If a change primarily helps ARC host itself as an MCP-compatible endpoint, it belongs in the edge runtime.

If a change primarily helps wrap an existing MCP server under ARC, it belongs in the adapter.
