# Phase 35 Context

## Goal

Support ACP/shared-payment-token style approvals with seller scoping and
bounded spend semantics.

## Current Code Reality

- `arc-core` already ships canonical governed transaction intent and approval
  token types, but governed receipt metadata does not yet carry typed commerce
  approval context.
- `arc-kernel` already has one adapter seam for payment rails plus truthful
  allow/deny/settlement handling for prepaid and hold-style flows.
- The governed validation path already enforces request target matching,
  approval-token binding, and optional `max_amount` checks, but it does not yet
  enforce seller-bound commerce scope.
- Phase 34 proved that operator visibility can ride on signed receipt metadata
  and `receipt_query` instead of a rail-specific reporting endpoint.
- There is no ACP-specific adapter today, so the current payment bridge cannot
  model seller-scoped shared-payment-token authorizations separately from x402.

## Decisions For This Phase

- Extend the governed intent/receipt model with typed commerce approval
  context rather than leaving ACP semantics buried inside ad hoc JSON.
- Keep ACP logic adapter-scoped in `crates/arc-kernel/src/payment.rs` while
  reusing the same generic `PaymentAdapter` contract used by x402.
- Add one first-class seller/payee constraint so grants can require a specific
  seller scope and the kernel can deny mismatches before payment or tool
  execution.
- Treat bounded commerce spend as explicit intent state: seller-scoped ACP
  requests must carry a shared payment token reference and a governed
  `max_amount` bound.
- Reuse receipt metadata and `receipt_query` coverage for operator visibility.

## Risks

- Adding commerce fields to the governed intent and receipt model touches
  `arc-core`, the kernel, and CLI regression tests.
- Seller-bound validation must remain narrow enough that it does not change the
  behavior of ordinary monetary grants or the x402 path.
- ACP hold/capture behavior must stay truthful when payment authorization
  succeeds but tool execution later aborts.

## Phase 35 Execution Shape

- 35-01: define the ACP/shared-payment-token adapter and commerce approval data
  model
- 35-02: enforce seller-bound bounded-spend semantics in governed runtime
  evaluation
- 35-03: add receipt-query, kernel regression coverage, and docs for ACP
  commerce flows
