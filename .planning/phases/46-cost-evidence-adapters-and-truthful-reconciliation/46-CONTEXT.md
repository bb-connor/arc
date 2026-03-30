# Phase 46 Context

## Goal

Implement pluggable billing-evidence adapters plus reconciliation rules that
preserve canonical execution receipt truth.

## Current Code Reality

- Phase 45 added immutable metered-billing quote context to governed intents
  and signed governed receipt metadata.
- ARC already has one mutable sidecar pattern for payment settlement
  reconciliation keyed by `receipt_id`, with operator reports and behavioral
  feed summaries that never rewrite the signed receipt.
- There is no equivalent persistence or reporting path yet for post-execution
  metered-cost evidence on non-rail tools, so `usageEvidence` is currently
  always absent in signed governed receipt metadata.
- `docs/research/DEEP_RESEARCH_1.md` and `docs/TOOL_PRICING_GUIDE.md` require a
  truthful two-source model: pre-execution quote plus post-execution evidence,
  with canonical execution receipts kept distinct from mutable operator
  reconciliation state.

## Decisions For This Phase

- Reuse the settlement-sidecar design: adapter evidence and reconciliation live
  in mutable store records keyed by `receipt_id`, not by patching signed
  receipt JSON.
- Make the first shipped adapter path generic and non-rail: a stable
  adapter-kind/evidence-id contract that external metering systems can post
  into trust-control.
- Fail closed on replay and drift: the same external evidence record cannot be
  bound to multiple receipts, and report surfaces must make missing evidence,
  over-cap usage, and quote-versus-actual mismatches explicit.
- Keep report rows honest about provenance by separating signed governed
  receipt metadata from mutable metered-evidence sidecars.

## Risks

- If report surfaces merge mutable usage evidence back into signed receipt
  fields, ARC will blur the exact trust boundary phase 45 introduced.
- If external evidence identifiers are not replay-safe, one billing record can
  be reused across receipts and poison later underwriting inputs.
- If reconciliation only compares evidence to the quote and ignores the
  receipt-side financial record, operators will miss cases where external
  metering and locally observed charges diverge.

## Phase 46 Execution Shape

- 46-01: add metered-evidence adapter contracts and SQLite persistence
- 46-02: implement reconciliation reports and trust-control ingest/query paths
- 46-03: document failure/replay semantics and add regression coverage
