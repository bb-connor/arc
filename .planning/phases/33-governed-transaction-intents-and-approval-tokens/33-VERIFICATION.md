---
phase: 33
slug: governed-transaction-intents-and-approval-tokens
status: passed
completed: 2026-03-26
---

# Phase 33 Verification

Phase 33 passed targeted verification for the first governed-transaction
runtime in `v2.6`.

## Automated Verification

- `cargo test -p arc-core`
- `cargo test -p arc-kernel governed`
- `cargo test -p arc-cli receipt_query`
- `rg -n "governed|approval token|governed_transaction" spec/PROTOCOL.md docs/AGENT_ECONOMY.md`

## Result

Passed. Phase 33 now satisfies `ECON-01`:

- governed transaction intent and approval-token artifacts exist as signed,
  first-class runtime inputs
- grant policy can explicitly require governed intent and threshold-based human
  approval
- allow, deny, and incomplete receipts preserve governed transaction evidence
  without overloading the `financial` metadata block
- trust-control receipt queries and the protocol/design docs surface the new
  governed metadata contract for operators
