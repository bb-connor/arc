---
phase: 310-progressive-tutorial-and-framework-integration
milestone: v2.81
created: 2026-04-13
status: complete
---

# Phase 310 Context

## Goal

Publish a tutorial that takes a developer from ARC basics through their first
delegation workflow, and upgrade the framework examples so they use the
official ARC SDKs instead of hand-rolled MCP transport code.

## Current Reality

- `examples/anthropic-sdk` and `examples/langchain` existed only as local,
  untracked drafts and both talked directly to `arc mcp serve` over stdio.
- Phase `309` already established the supported local runtime topology:
  `arc trust serve` plus `arc mcp serve-http` around the example upstream tool.
- The public documentation surface already described federated delegation via
  `arc trust federated-delegation-policy-create` and
  `arc trust federated-issue --upstream-capability-id ...`, but there was no
  progressive tutorial that connected that lane back to the basic local demo.

## Boundaries

- Reuse the phase `309` hosted-edge topology rather than inventing a second
  tutorial/runtime path.
- Keep the framework examples focused on SDK-backed governed tool calls and
  receipt lookup; do not expand them into broader product demos.
- Preserve the unrelated dirty planning, docs, and runtime work already in the
  repository.

## Key Risks

- If the examples still talk raw MCP transport, the phase misses the roadmap's
  "official SDKs" requirement even if they continue to work functionally.
- The tutorial must be honest about the currently exposed delegation lane; it
  cannot imply a local single-command child-issuance path that does not exist.
- Example install instructions need to handle repo-local SDK packages cleanly
  without depending on unpublished registry state.

## Decision

Anchor the whole phase around the already-qualified hosted HTTP edge. The
tutorial will use the Docker quickstart and hosted-edge commands for the
introductory flow, then explain delegation through the concrete federated
continuation CLI. The Anthropic, LangChain, and OpenAI-compatible examples will
all consume the hosted edge through the official ARC SDK clients and share one
scripted verification lane.
