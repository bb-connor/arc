---
phase: 40-cross-org-reputation-distribution-and-federation-guardrails
plan: 02
subsystem: imported-reputation-surfaces
tags:
  - reputation
  - trust-control
  - federation
requires:
  - 40-01
provides:
  - Local and trust-control reputation outputs that expose imported trust separately
  - SQLite subject-corpus queries over imported federated evidence shares
  - Operator-visible provenance, acceptance state, and attenuated imported scores
key-files:
  modified:
    - crates/arc-cli/src/reputation.rs
    - crates/arc-cli/src/trust_control.rs
    - crates/arc-store-sqlite/src/receipt_store.rs
    - crates/arc-cli/tests/local_reputation.rs
requirements-completed:
  - TRUST-04
completed: 2026-03-26
---

# Phase 40 Plan 02 Summary

Phase 40-02 turned the imported-trust model into operator-visible CLI and
trust-control behavior.

## Accomplishments

- added receipt-store queries that materialize imported subject corpora from
  federated evidence shares
- surfaced `importedTrust` on `arc reputation local` and
  `arc reputation compare`
- surfaced the same imported-trust report through trust-control local and
  comparison endpoints
- added regression coverage proving accepted and rejected imported signals keep
  their provenance, reasons, and attenuated scores

## Verification

- `cargo test -p arc-cli --test local_reputation`
