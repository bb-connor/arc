---
phase: 40-cross-org-reputation-distribution-and-federation-guardrails
plan: 01
subsystem: imported-reputation-model
tags:
  - reputation
  - federation
  - trust
requires: []
provides:
  - A typed imported-trust policy and signal model with explicit provenance
  - Attenuated imported reputation signals derived from federated evidence shares
  - A conservative default policy that rejects proofless or stale remote trust
key-files:
  modified:
    - crates/arc-reputation/src/model.rs
    - crates/arc-reputation/src/compare.rs
    - crates/arc-cli/src/reputation.rs
requirements-completed:
  - TRUST-04
completed: 2026-03-26
---

# Phase 40 Plan 01 Summary

Phase 40-01 defined imported reputation as an explicit evidence-backed signal
instead of a hidden extension of local score state.

## Accomplishments

- added typed imported-trust provenance, policy, and signal models in
  `arc-reputation`
- defined conservative default guardrails for imported trust, including proof
  requirements, age limits, and attenuation
- implemented imported-signal derivation from federated evidence shares while
  preserving the local/native reputation corpus as separate truth
- threaded imported trust into CLI comparison structures without inventing a
  synthetic global score

## Verification

- `cargo test -p arc-reputation`
