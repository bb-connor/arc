---
phase: 35
slug: acp-bridge-and-bounded-commerce-spend
status: passed
completed: 2026-03-26
---

# Phase 35 Verification

Phase 35 passed targeted verification for the ACP/shared-payment-token bridge
in `v2.6`.

## Automated Verification

- `cargo test -p arc-core governed`
- `cargo test -p arc-kernel acp`
- `cargo test -p arc-kernel governed_monetary`
- `cargo test -p arc-cli receipt_query`
- `rg -n "ACP|shared payment token|seller" docs/AGENT_ECONOMY.md spec/PROTOCOL.md .planning/phases/35-acp-bridge-and-bounded-commerce-spend/35-CONTEXT.md`

## Result

Passed. Phase 35 now satisfies `ECON-03`:

- ARC can represent seller-scoped commerce approvals as first-class governed
  intent, receipt, and payment-authorization data
- governed runtime validation enforces seller scope, shared payment token
  presence, and explicit bounded spend before payment or tool execution
- ACP allow and deny flows preserve truthful payment-state versus
  tool-execution semantics
- trust-control receipt queries surface ACP payment metadata and governed
  commerce approval evidence intact for operators
