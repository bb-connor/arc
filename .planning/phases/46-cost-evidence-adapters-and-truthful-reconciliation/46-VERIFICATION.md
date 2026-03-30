status: passed
completed: 2026-03-27

# Phase 46 Verification

## Commands

- `cargo test -p arc-kernel operator_report -- --nocapture`
- `cargo test -p arc-cli --test receipt_query -- --nocapture`
- `cargo fmt --all`
- `git diff --check -- crates/arc-kernel/src/operator_report.rs crates/arc-kernel/src/lib.rs crates/arc-kernel/src/receipt_store.rs crates/arc-store-sqlite/src/receipt_store.rs crates/arc-cli/src/trust_control.rs crates/arc-cli/tests/receipt_query.rs spec/PROTOCOL.md docs/TOOL_PRICING_GUIDE.md .planning/phases/46-cost-evidence-adapters-and-truthful-reconciliation/46-CONTEXT.md .planning/phases/46-cost-evidence-adapters-and-truthful-reconciliation/46-01-PLAN.md .planning/phases/46-cost-evidence-adapters-and-truthful-reconciliation/46-02-PLAN.md .planning/phases/46-cost-evidence-adapters-and-truthful-reconciliation/46-03-PLAN.md`

## Result

- metered evidence attachments persist in mutable sidecar state
- replayed evidence IDs are rejected across receipts
- non-metered receipts reject evidence attachment
- operator reports and behavioral feeds expose quote-versus-actual
  reconciliation without mutating signed receipt query output

## Follow-On

- phase 47 can now map governed approvals and delegated call-chain context into
  external authorization-details style representations using truthful cost
  evidence that already exists as separate mutable state
