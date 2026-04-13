---
phase: 305-async-kernel-migration
created: 2026-04-13
---

# Phase 305 Validation

## Required Evidence

- `ArcKernel::evaluate_tool_call` is an `async fn` taking `&self`.
- Session state, receipt logs, and mutable stores are accessed through shared
  synchronization primitives rather than exclusive kernel borrows.
- At least one test runs two concurrent evaluations against one shared kernel
  and proves both complete without deadlock or forced serialization.

## Verification Commands

- `cargo check -p arc-kernel -p arc-mcp-edge -p arc-cli -p arc-control-plane`
- `cargo test -p arc-kernel --tests`
- `cargo test -p arc-kernel kernel::tests:: -- --nocapture`
- `cargo test -p arc-mcp-edge --tests`
- `cargo check --workspace`

## Regression Focus

- Session lifecycle and inflight tracking
- Nested-flow tool calls
- Receipt persistence and checkpoint creation
- Budget charge / reverse / reconcile logic
- `arc-mcp-edge` session-backed tool-call routing
