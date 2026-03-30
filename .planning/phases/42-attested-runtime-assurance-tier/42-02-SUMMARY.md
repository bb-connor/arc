---
phase: 42-attested-runtime-assurance-tier
plan: 02
subsystem: runtime-assurance-enforcement
tags:
  - attestation
  - issuance
  - governed-transactions
requires:
  - 42-01
provides:
  - Assurance-tier-aware policy evaluation
  - Attestation-gated capability issuance and scope ceilings
  - Fail-closed governed enforcement for runtime assurance on economic grants
key-files:
  modified:
    - crates/arc-policy/src/evaluate/context.rs
    - crates/arc-policy/src/evaluate/matchers.rs
    - crates/arc-cli/src/policy.rs
    - crates/arc-cli/src/issuance.rs
    - crates/arc-cli/src/trust_control.rs
    - crates/arc-kernel/src/lib.rs
requirements-completed:
  - RISK-02
completed: 2026-03-26
---

# Phase 42 Plan 02 Summary

Phase 42-02 made runtime assurance a real enforcement path across issuance,
policy evaluation, and governed execution.

## Accomplishments

- policy evaluation can now require or prefer explicit runtime assurance tiers
  on tool access decisions without inventing a second trust engine
- HushSpec loading now materializes named runtime-assurance issuance tiers into
  concrete scope ceilings enforced during capability issuance
- trust-control and local issuance both accept optional runtime attestation
  evidence and reject scope requests that exceed the ceiling for the resolved
  attestation tier
- economically sensitive grants issued above `none` now carry
  `MinimumRuntimeAssurance(...)`, and the kernel fails closed when governed
  requests omit, expire, or undershoot the required attestation tier
- governed receipt metadata records the resolved runtime-assurance tier,
  verifier, and evidence digest for later operator inspection

## Verification

- `cargo test -p arc-kernel governed_monetary -- --nocapture`
