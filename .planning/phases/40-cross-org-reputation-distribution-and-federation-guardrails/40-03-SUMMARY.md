---
phase: 40-cross-org-reputation-distribution-and-federation-guardrails
plan: 03
subsystem: imported-reputation-docs-and-e2e
tags:
  - docs
  - federation
  - reputation
requires:
  - 40-01
  - 40-02
provides:
  - Operator guidance for conservative imported-trust inspection
  - End-to-end export/import regression coverage for imported reputation
  - A clearer portable-trust story tying identity, passports, certification, and reputation together
key-files:
  modified:
    - docs/IDENTITY_FEDERATION_GUIDE.md
    - docs/AGENT_PASSPORT_GUIDE.md
    - crates/arc-cli/tests/local_reputation.rs
    - crates/arc-cli/tests/evidence_export.rs
requirements-completed:
  - TRUST-04
  - TRUST-05
completed: 2026-03-26
---

# Phase 40 Plan 03 Summary

Phase 40-03 closed the `v2.7` reputation-sharing contract with operator docs
and end-to-end regressions.

## Accomplishments

- documented imported trust as evidence-backed, issuer-scoped, and explicitly
  attenuated rather than a universal score
- clarified that imported reputation does not rewrite local receipt or budget
  truth
- added end-to-end export/import coverage proving federated evidence packages
  populate imported trust in downstream reputation inspection
- added regression coverage for fail-closed proof guardrails on imported
  signals

## Verification

- `cargo test -p arc-cli --test evidence_export`
