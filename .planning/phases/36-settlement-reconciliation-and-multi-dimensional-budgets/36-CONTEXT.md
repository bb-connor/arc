# Phase 36 Context

## Goal

Expose settlement reconciliation and add at least one richer budget dimension
beyond money alone.

## Current Code Reality

- Signed receipts already carry canonical `financial.settlement_status`, and
  the operator compliance report already counts pending and failed settlements.
- Trust-control does not yet expose a settlement backlog with receipt-level
  rows, nor any sidecar action surface for operators to mark a pending or
  failed settlement as reconciled without mutating the signed receipt.
- Budget utilization reports already expose invocation and cost fields, but the
  non-monetary side is not modeled as an explicit first-class dimension.
- Runtime enforcement already composes monetary limits with `max_invocations`,
  so the missing work is productizing that second dimension rather than
  inventing a new enforcement primitive from scratch.

## Decisions For This Phase

- Add reconciliation state as a mutable sidecar record keyed by `receipt_id`,
  keeping signed receipt truth immutable while still allowing operator action.
- Expose settlement backlog details both as a dedicated report and inside the
  composite operator report so phase 36 is queryable without introducing a new
  payment-rail-specific subsystem.
- Promote invocation budgets to an explicit budget-dimension profile in
  operator reporting, alongside money, rather than relying on ad hoc fields.
- Keep the new state in the SQLite receipt store used by trust-control so the
  phase lands on the existing operator path.

## Risks

- Sidecar reconciliation state must never be confused with signed receipt
  truth; the report needs to separate receipt settlement status from operator
  reconciliation status.
- Query/report additions touch `arc-kernel`, `arc-store-sqlite`, and
  `arc-cli` together, so schema drift is an easy failure mode.
- Reusing invocation budgets as the richer dimension only works if the report
  surfaces them as a first-class dimension rather than as incidental counters.

## Phase 36 Execution Shape

- 36-01: add settlement reconciliation storage and query/action surfaces
- 36-02: make invocation budgets a first-class non-monetary dimension in
  operator reporting
- 36-03: add trust-control regression coverage and docs for reconciliation plus
  budget dimensions
