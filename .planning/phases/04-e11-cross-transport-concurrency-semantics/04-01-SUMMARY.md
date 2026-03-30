---
phase: 04-e11-cross-transport-concurrency-semantics
plan: 01
subsystem: concurrency-semantics
tags:
  - ownership
  - lineage
  - remote-mcp
  - tasks
  - diagnostics
requires: []
provides:
  - Explicit transport-neutral ownership snapshots across task and remote-session surfaces
  - Serialized task lineage for edge and nested-flow tasks
  - Related-task terminal metadata that carries ownership lineage, not only task ids
  - Regression coverage for direct, wrapped, and remote ownership semantics plus a green workspace qualification run
requirements_completed:
  - CON-01
completed: 2026-03-20T02:53:04Z
---

# Phase 4 Plan 04-01: E11 Ownership Model Summary

**ARC now exposes one concrete ownership model across direct, wrapped, and remote paths: request-owned session work is explicit on remote diagnostics, task-owned work is explicit on task surfaces, and terminal task results carry lineage metadata instead of collapsing to bare task ids**

## Accomplishments

- Extended edge task serialization to keep ownership lineage visible through `ownerSessionId`, `ownerRequestId`, and `parentRequestId`
- Extended nested-flow transport tasks to serialize `ownerRequestId` and `parentRequestId`, so wrapped task surfaces no longer drop lineage
- Added canonical request-ownership snapshots plus live request-stream / notification-stream state to remote session-trust diagnostics
- Carried ownership lineage into related-task terminal `_meta` for `tasks/result` responses
- Added regression coverage for remote request-stream lease visibility, GET notification attachment, nested-flow task lineage, and terminal cancelled-task ownership
- Re-qualified the full workspace after the ownership-model changes

## Key Files

- `crates/arc-mcp-adapter/src/edge.rs`
- `crates/arc-mcp-adapter/src/transport.rs`
- `crates/arc-cli/src/remote_mcp.rs`
- `crates/arc-cli/tests/mcp_serve.rs`
- `crates/arc-cli/tests/mcp_serve_http.rs`
- `docs/epics/E11-cross-transport-concurrency-semantics.md`
- `.planning/ROADMAP.md`
- `.planning/REQUIREMENTS.md`
- `.planning/STATE.md`

## Decisions Made

- Remote session diagnostics must expose the canonical request ownership shape, not only transport-specific stream-mode enums
- Ownership lineage must stay attached to terminal task results so clients can understand attribution without a follow-up `tasks/get`
- Wrapped nested-flow tasks only serialize the lineage the transport actually owns: request lineage, not fabricated session ids

## Verification

- `cargo fmt --all -- --check`
- `cargo test -p arc-mcp-adapter -- --nocapture`
- `cargo test -p arc-cli --test mcp_serve -- --nocapture`
- `cargo test -p arc-cli --test mcp_serve_http -- --nocapture`
- `cargo test --workspace`

## Next Phase Readiness

- `CON-01` is now closed with explicit code and regression coverage
- Phase 4 can focus entirely on `CON-03`: durable late async completion and late-event sourcing
