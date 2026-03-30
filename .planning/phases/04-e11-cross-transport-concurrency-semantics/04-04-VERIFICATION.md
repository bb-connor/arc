---
phase: 04-e11-cross-transport-concurrency-semantics
plan: 04
verified: 2026-03-20T03:29:52Z
status: passed
requirements:
  - CON-03
---

# Phase 4 Plan 04-04 Verification Report

**Phase Goal:** Make task ownership, stream ownership, cancellation, and late async completion behave the same way across direct, wrapped, stdio, and remote paths.
**Scoped Gate:** Plan 04-04 - Add durable async completion sources and late-event coverage for native and wrapped paths.
**Status:** passed

## Verified Truths

1. Kernel `Session` now owns accepted URL-completion state and late-event queues instead of leaving that bookkeeping to edge-local scratch maps.
2. Direct/in-process embedders can progress background tasks and drain late notifications through a session-owned runtime surface after `tools/call` has already returned.
3. Wrapped stdio still forwards idle resource/catalog/elicitation notifications correctly after the session-owned late-event refactor.
4. Remote HTTP now proves a wrapped MCP server can emit a resource notification after the original POST `tools/call` response has already completed, and the GET session stream still receives it.
5. A full `cargo test --workspace` rerun passed after the late-event ownership changes.

## Commands Run

- `cargo fmt --all -- --check`
- `cargo test -p arc-mcp-adapter -- --nocapture`
- `cargo test -p arc-cli --test mcp_serve -- --nocapture`
- `cargo test -p arc-cli --test mcp_serve_http -- --nocapture`
- `cargo test --workspace`

## Notes

- The strongest new proof in this slice is the hosted HTTP regression where the wrapped server emits `notifications/resources/list_changed` after the originating POST `tools/call` has already returned; that was the clearest remaining transport-matrix gap before Phase 4 could be closed.
