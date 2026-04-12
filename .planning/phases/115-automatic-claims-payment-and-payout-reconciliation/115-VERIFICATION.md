# Phase 115 Verification

Phase `115` is complete.

## What changed

- Added signed liability claim payout instruction and payout receipt artifacts.
- Persisted payout instruction and payout receipt state in the liability claim
  workflow store.
- Exposed payout issuance through trust-control routes and liability-market CLI
  commands.
- Extended claim-workflow reporting and CLI output with payout summary and row
  state.
- Increased trust-control runtime worker stack size to support deeply nested
  signed liability workflow artifacts during service serialization.
- Hardened the liability claim workflow integration test to run on a larger
  stack and to exercise the payout lane end to end.

## Validation

Passed:

- `cargo check -p arc-core -p arc-store-sqlite -p arc-cli`
- `CARGO_INCREMENTAL=0 cargo test -p arc-cli --test receipt_query test_liability_claim_workflow_surfaces -- --exact --nocapture`
- `CARGO_INCREMENTAL=0 cargo test -p arc-cli --test receipt_query test_liability_claim_rejects_oversized_claims_and_invalid_disputes -- --exact --nocapture`
- `git diff --check`

## Outcome

`LIVEX-03` is now satisfied. ARC has a bounded automatic claims-payment lane
with separate payout intent and payout reconciliation artifacts, while
recovery clearing remains deferred to phase `116`.
