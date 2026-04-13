---
phase: 305-async-kernel-migration
milestone: v2.80
created: 2026-04-13
status: active
---

# Phase 305 Context

## Goal

Move the ARC kernel onto an async `&self` tool-evaluation path so concurrent
callers no longer require an exclusive mutable borrow of the entire kernel.

## Current Reality

- `ArcKernel` still stores sessions, receipt logs, checkpoint counters, and
  mutable store trait objects directly in the struct.
- The main tool-call entrypoint is
  `ArcKernel::evaluate_tool_call(&mut self, ...)`.
- The session-backed production path also depends on mutable entrypoints:
  `evaluate_session_operation`, `evaluate_tool_call_operation_with_nested_flow_client`,
  and the session lifecycle/bookkeeping APIs.
- `BudgetStore`, `ReceiptStore`, and `RevocationStore` still expose runtime
  mutation through `&mut self`.

## Boundaries

- This phase must preserve current behavior and public semantics apart from
  enabling concurrent access.
- Build-time configuration can remain `&mut self`.
- Runtime/session/receipt/budget state must move behind interior mutability.
- `arc-mcp-edge` is the highest-risk downstream caller and must keep working.

## Key Risks

- Session bookkeeping is spread across many APIs and currently assumes direct
  `&mut HashMap<SessionId, Session>` access.
- Receipt persistence and checkpoint sequencing currently rely on mutable
  shared fields.
- The tool-call path still traverses synchronous tool-server and store traits,
  so the async migration must not accidentally serialize everything behind one
  coarse kernel-wide lock.

## Decision

Use interior mutability inside `ArcKernel` rather than introducing a new
single-owner async actor. This matches the roadmap requirement that session
state, receipt log, and budget stores use `RwLock`, `Mutex`, atomics, or
equivalent shared-state primitives.
