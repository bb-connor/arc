---
phase: 42-attested-runtime-assurance-tier
plan: 01
subsystem: runtime-assurance-contract
tags:
  - attestation
  - policy
  - portable-trust
requires: []
provides:
  - A normalized runtime-attestation evidence model
  - Explicit operator-visible runtime assurance tiers
  - Policy schema support for assurance-tier-aware issuance and evaluation
key-files:
  modified:
    - crates/arc-core/src/capability.rs
    - crates/arc-core/src/receipt.rs
    - crates/arc-credentials/src/artifact.rs
    - crates/arc-policy/src/models.rs
requirements-completed:
  - RISK-02
completed: 2026-03-26
---

# Phase 42 Plan 01 Summary

Phase 42-01 defined runtime attestation as a normalized policy input instead
of a transport- or vendor-specific subsystem.

## Accomplishments

- added explicit `RuntimeAssuranceTier` values plus normalized
  `RuntimeAttestationEvidence` that preserve verifier identity, validity
  window, evidence digest, optional runtime identity, and opaque claims
- extended governed transaction intents and governed receipt metadata so
  attestation evidence and its resolved assurance tier can travel with
  issuance and execution decisions
- added `Constraint::MinimumRuntimeAssurance(...)` so stronger issuance can be
  rebound to later governed execution instead of acting as a one-time trust
  upgrade
- extended the policy model with assurance-tier-aware tool rules and a
  top-level `extensions.runtime_assurance` contract for named issuance tiers

## Verification

- `cargo test -p arc-policy`
