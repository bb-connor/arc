---
phase: 305-async-kernel-migration
created: 2026-04-13
---

# Phase 305 Research

## Findings

- The dominant exclusive path is still the tool-evaluation pipeline in
  `crates/arc-kernel/src/kernel/mod.rs` plus the session-backed wrappers in
  `crates/arc-kernel/src/kernel/session_ops.rs`.
- The largest runtime mutation domains are:
  `sessions`, `receipt_log`, `child_receipt_log`, `budget_store`,
  `revocation_store`, `receipt_store`, `session_counter`,
  `checkpoint_seq_counter`, and `last_checkpoint_seq`.
- `ToolServerConnection`, `PaymentAdapter`, `PriceOracle`, and
  `CapabilityAuthority` are already `Send + Sync`, so the most urgent shared
  access work is on kernel-owned state, not those trait objects.
- `arc-mcp-edge` is the highest-risk caller because it drives the session path,
  nested-flow path, and late-event queueing from one runtime object.
- Existing async usage inside the kernel is limited; the price-oracle bridge
  currently blocks on async futures instead of awaiting them directly.

## Chosen Approach

1. Convert kernel-owned runtime state to interior mutability.
2. Change runtime/session APIs from `&mut self` to `&self` where they mutate
   through those shared primitives.
3. Flip `ArcKernel::evaluate_tool_call` to `async fn`.
4. Keep a narrow synchronous compatibility wrapper for legacy synchronous
   callers while the wider stack finishes migrating.
5. Add an explicit concurrent evaluation test on a shared kernel instance.

## Rejected Approach

- A dedicated async kernel actor/handle would minimize call-site churn, but it
  would violate the roadmap’s explicit requirement that the kernel’s own
  session, receipt, and budget state move behind interior mutability.
