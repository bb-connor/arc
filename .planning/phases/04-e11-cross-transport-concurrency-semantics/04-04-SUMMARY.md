---
phase: 04-e11-cross-transport-concurrency-semantics
plan: 04
subsystem: concurrency-semantics
tags:
  - late-async
  - session-state
  - remote-http
  - wrapped-mcp
requires:
  - CON-01
  - CON-02
  - CON-04
provides:
  - Kernel-session ownership for pending URL completions and late tool-server notifications
  - Direct in-process runtime draining that progresses background work and surfaces late events without request-local bridges
  - Remote HTTP regression coverage for wrapped notifications emitted after POST `tools/call` has already completed
requirements_completed:
  - CON-03
completed: 2026-03-20T03:29:52Z
---

# Phase 4 Plan 04-04: E11 Durable Async Completion Summary

**ARC late async behavior is now session-owned enough to close Phase 4: kernel sessions own pending URL completions and late event queues, the direct edge drains those session queues explicitly, and remote HTTP proves wrapped notifications can still arrive after the originating POST turn is already over**

## Accomplishments

- Added kernel-session late-event state so accepted URL completions and tool-server notifications are stored on `Session`, not just in edge-local maps
- Added kernel helpers to register pending URL completions, queue tool-server events per session, and drain late session events explicitly
- Routed direct and wrapped late-event sources through session-owned queues before emitting JSON-RPC notifications
- Preserved the direct/in-process runtime drain surface so embedders can advance background work and collect late notifications without a transport loop
- Added a remote HTTP regression where a wrapped MCP server responds to `tools/call` first and only later emits `notifications/resources/list_changed`, with the hosted GET stream receiving that late event
- Re-qualified wrapped stdio, remote HTTP, adapter, and full-workspace gates after the session-owned late-event change

## Key Files

- `crates/arc-kernel/src/session.rs`
- `crates/arc-kernel/src/lib.rs`
- `crates/arc-mcp-adapter/src/edge.rs`
- `crates/arc-cli/tests/mcp_serve_http.rs`
- `.planning/ROADMAP.md`
- `.planning/REQUIREMENTS.md`
- `.planning/STATE.md`
- `docs/epics/E11-cross-transport-concurrency-semantics.md`

## Decisions Made

- Pending URL completions belong to kernel session state so late completion routing survives beyond one edge request turn
- Late tool-server events should be normalized into session-owned queues before the edge turns them back into JSON-RPC notifications
- Remote HTTP needs an explicit proof that wrapped late notifications still surface on the session stream after POST request ownership has ended

## Verification

- `cargo fmt --all -- --check`
- `cargo test -p arc-mcp-adapter -- --nocapture`
- `cargo test -p arc-cli --test mcp_serve -- --nocapture`
- `cargo test -p arc-cli --test mcp_serve_http -- --nocapture`
- `cargo test --workspace`

## Next Phase Readiness

- Phase 4 is complete
- The remaining milestone work is Phase 6 / `E14`: release qualification, guarantees, failure-mode documentation, and go/no-go evidence
