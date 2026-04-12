# Phase 164: x402 Surface, Circle Nanopayments, and ERC-4337 Paymaster Compatibility - Context

**Gathered:** 2026-04-02
**Status:** Ready for planning

<domain>
## Phase Boundary

Close `v2.38` with one bounded machine-payment and gas-abstraction
compatibility layer over governed ARC settlement truth.

</domain>

<decisions>
## Implementation Decisions

### Payment Interop
- Project settlement dispatch into x402 requirements instead of treating x402
  as an alternate receipt ledger.
- Keep Circle nanopayments bounded to explicit operator-managed custody.

### Gas Abstraction
- Treat EIP-3009 and ERC-4337/paymaster support as compatibility preparation
  and policy evaluation only.
- Keep reimbursement and deduction posture explicit and bounded.

### Milestone Closure
- Publish one shared qualification matrix over Functions, automation, CCIP,
  and payment interop.
- Close the milestone with runbook, release, protocol, and planning updates
  that match the implemented runtime.

</decisions>

<code_context>
## Existing Code Insights

- `crates/arc-settle/src/payments.rs` is the natural place for settlement-
  side interoperability preparation and policy evaluation.
- `docs/AGENT_ECONOMY.md` already frames x402 as truthful payment interop
  rather than ARC becoming a native payment rail.
- `docs/research/ARC_LINK_FUTURE_TRACKS.md` treats Circle and ERC-4337 as
  optional compatibility tracks that must stay explicit about custody and gas
  posture.

</code_context>

<deferred>
## Deferred Ideas

- live production facilitator integrations
- automatic Circle or ERC-4337 execution without operator review
- universal gas sponsorship or arbitrary payment-facilitator discovery

</deferred>
