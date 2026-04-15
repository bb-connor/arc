# Phase 420 Context: Governed Provenance Truth Closure

## Why This Phase Exists

ARC signs governed context today, but not every signed provenance field is an
authenticated upstream fact. The bounded release needs one explicit provenance
model so reviewer packs, authorization-context exports, and receipt docs do not
smuggle caller assertions into stronger evidentiary claims.

Phase `420` exists to close that gap.

## Required Outcomes

1. Distinguish asserted, observed, and verified provenance, or explicitly
   narrow the bounded release to preserved caller context where verification
   does not exist.
2. Reconcile governed call-chain, authorization-context, and reviewer-pack
   semantics to the same provenance model.
3. Ensure no ship-facing doc or contract surface treats caller-supplied
   governed provenance as authenticated upstream truth unless that stronger
   verification class ships.

## Existing Assets

- `docs/review/04-provenance-call-chain-remediation.md`
- `crates/arc-core-types/src/capability.rs`
- `crates/arc-kernel/src/receipt_support.rs`
- `crates/arc-store-sqlite/src/receipt_store.rs`
- authorization-context and reviewer-pack docs/tests

## Gaps To Close

- signed governed provenance still mixes local observation and caller
  assertion
- evidence/report surfaces do not yet share one explicit provenance taxonomy
- bounded release docs do not yet state the narrower truth boundary crisply

## Requirements Mapped

- `PROV5-01`
- `PROV5-02`

## Exit Criteria

This phase is complete only when bounded ARC evidence surfaces state clearly
what ARC actually observed, what callers asserted, and what was independently
verified.
