# Phase 34 Context

## Goal

Bridge ARC policy to x402-style prepaid API flows without falsifying execution
or settlement truth.

## Current Code Reality

- `arc-kernel` already ships a concrete `X402PaymentAdapter` in
  `crates/arc-kernel/src/payment.rs`.
- The adapter currently performs a thin prepaid HTTP authorize call and marks
  the rail as settled when the response says so, but the authorize request body
  does not yet carry governed intent context.
- `ArcKernel` already supports optional `PaymentAdapter` installation and
  truthful prepaid receipt semantics, but the existing prepaid tests use the
  in-process `PrepaidSettledPaymentAdapter` stub rather than the real x402
  adapter.
- `arc-cli` has no explicit x402 configuration surface today. The phase should
  avoid leaking x402-specific logic across the kernel, but it should harden the
  adapter contract and expose enough configuration/wiring for real use.
- Trust-control receipt queries already surface raw receipt metadata, so
  operator visibility for x402 flows can ride on receipt metadata rather than a
  new reporting API.

## Decisions For This Phase

- Keep x402 logic adapter-scoped in `crates/arc-kernel/src/payment.rs`.
- Bind governed transaction context into the x402 authorize payload so prepaid
  rail authorization is cryptographically tied to the same governed request the
  kernel evaluates.
- Validate phase 34 with real `X402PaymentAdapter` kernel tests, not just stub
  adapters.
- Use receipt-query coverage to prove x402 payment metadata is operator-visible
  without adding a new bespoke reporting endpoint.

## Risks

- Changing the payment-adapter authorize contract touches kernel wiring and all
  test adapters.
- Receipt semantics must remain truthful: 402 or authorization failures deny
  before tool execution, while successful prepaid authorizations preserve
  settled references even when execution later aborts.

## Phase 34 Execution Shape

- 34-01: harden the x402 adapter request/config contract
- 34-02: bind governed requests to the prepaid x402 execution path and cover
  truthful allow/deny semantics in kernel tests
- 34-03: prove x402 payment metadata is visible to operators via receipt-query
  coverage and document the flow
