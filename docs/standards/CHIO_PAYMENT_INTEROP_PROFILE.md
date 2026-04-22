# Chio Payment Interop Profile

## Purpose

This profile closes phase `164` by freezing Chio's bounded machine-payment and
gas-abstraction compatibility layer.

These surfaces sit on top of governed Chio dispatch and settlement truth. They
never replace signed receipts, explicit approval context, or the official web3
dispatch contract.

## Shipped Boundary

Chio now ships four bounded payment-interop capabilities:

- projection of one governed settlement dispatch into an x402 payment-requirement
  object
- preparation of one EIP-3009 `transferWithAuthorization` digest for
  explicit gasless token movement review
- evaluation of one Circle nanopayment candidate only when operator-managed
  custody is explicit
- evaluation of one ERC-4337/paymaster compatibility record only when gas
  sponsorship and reimbursement remain within bounded policy

## Supported Guardrails

The shipped interop layer requires:

- a facilitator URL and resource identifier for x402
- explicit accepted-token lists rather than ambient token discovery
- explicit chain allowlists for Circle-managed custody and paymaster use
- explicit reimbursement ceilings for paymaster compatibility
- explicit settlement-side deduction semantics for any sponsored gas posture

## Reference Artifacts

- `docs/standards/CHIO_X402_REQUIREMENTS_EXAMPLE.json`
- `docs/standards/CHIO_EIP3009_TRANSFER_WITH_AUTHORIZATION_EXAMPLE.json`
- `docs/standards/CHIO_CIRCLE_NANOPAYMENT_EXAMPLE.json`
- `docs/standards/CHIO_4337_PAYMASTER_COMPAT_EXAMPLE.json`
- `docs/standards/CHIO_WEB3_AUTOMATION_QUALIFICATION_MATRIX.json`

## Failure Posture

The interop layer fails closed when:

- an x402 surface omits facilitator, resource, or accepted-token scope
- Circle-managed custody is not explicitly declared
- the dispatch chain or token falls outside the bounded policy
- the candidate amount exceeds the bounded nanopayment ceiling
- requested gas sponsorship or reimbursement exceeds the bounded paymaster
  policy
- gas reimbursement would be treated as an implicit hidden deduction

## Non-Goals

This profile does not claim:

- a generic payment-facilitator marketplace
- implicit custody handoff to Circle or another provider
- universal gas sponsorship for all Chio calls
- mutation of signed Chio receipts to reflect off-protocol facilitator state

The shipped layer is interoperability only.
