# MERCURY Renewal Qualification Operations

**Date:** 2026-04-04  
**Milestone:** `v2.59`

---

## Purpose

The renewal-qualification lane packages one bounded Mercury renewal motion
while preserving the same delivery-continuity truth chain. This runbook
defines the minimum artifact set, outcome-review rules, renewal-approval
boundary, reference-reuse posture, and fail-closed expansion-boundary handoff
for that lane.

---

## Required Bundle Components

Every `renewal-qualification export` bundle must include:

- one renewal-qualification profile
- one renewal-qualification package
- one renewal-boundary freeze artifact
- one renewal-qualification manifest
- one outcome-review summary
- one renewal-approval artifact
- one reference-reuse discipline artifact
- one expansion-boundary handoff artifact
- one delivery-continuity package
- one account-boundary freeze artifact
- one delivery-continuity manifest
- one outcome-evidence summary
- one renewal-gate artifact
- one delivery-escalation brief
- one customer-evidence handoff artifact
- one selective-account-activation package
- one broader-distribution package
- one reference-distribution package
- one controlled-adoption package
- one release-readiness package
- one trust-network package
- one assurance-suite package
- one proof package
- one inquiry package
- one inquiry verification report
- one reviewer package
- one qualification report

The bundle is incomplete if any of those files are missing, inconsistent, or
cannot be matched back to the same workflow.

---

## Operating Boundary

- qualification owner: `mercury-renewal-qualification`
- review owner: `mercury-outcome-review`
- expansion owner: `mercury-expansion-boundary`

The qualification owner controls the bounded renewal motion and supported
claim. Outcome review owns the hard go/no-go approval for renewal reuse.
Expansion boundary receives the bundle only after approval is current and the
scope remains bounded to one previously stabilized account.

---

## Fail-Closed Rules

The renewal-qualification path must fail closed when:

- the profile and package disagree on renewal motion or review surface
- supported claims expand beyond the bounded evidence-backed sentence
- the renewal approval is missing or stale before claim reuse
- the manifest omits delivery-continuity, proof, inquiry, or reviewer files
- the motion widens beyond one account or one outcome-review bundle

Recovery posture:

1. stop reuse of the renewal bundle immediately
2. regenerate the renewal-qualification export from the canonical
   delivery-continuity lane
3. require a fresh outcome-review approval before reuse

---

## Deferred Operations

This runbook does not authorize:

- multiple renewal motions or review surfaces
- a generic customer-success suite, CRM workflow, or account-management
  platform
- channel marketplaces or multi-account renewal programs
- a merged Mercury and ARC-Wall shell
- ARC-side commercial control surfaces
- broad customer-health or universal renewal-performance claims

Those remain separate decisions, not hidden responsibilities inside `v2.59`.
