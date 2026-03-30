status: passed
completed: 2026-03-27

# Phase 47 Verification

## Commands

- `cargo fmt --all`
- `cargo test -p arc-kernel operator_report -- --nocapture`
- `cargo test -p arc-kernel call_chain -- --nocapture`
- `cargo test -p arc-cli --test receipt_query -- --nocapture`
- `git diff --check`

## Result

- governed call-chain context is bound into receipt metadata and rejected when
  malformed
- authorization-context reports derive external authorization details and
  transaction context from signed governed receipts
- trust-control, composite operator reports, and CLI output expose the same
  derived projection without a second writable authorization document

## Follow-On

- phase 48 can now focus on qualification, partner-facing artifacts, and
  milestone closeout for the broader economic interop story
