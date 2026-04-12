# MERCURY Renewal Qualification

**Date:** 2026-04-04  
**Milestone:** `v2.59`  
**Audience:** product, revenue, renewal review, customer evidence, and operators

---

## Purpose

This document freezes the bounded Mercury renewal-qualification lane selected
for `v2.59`.

The lane is intentionally narrow:

- one renewal motion only: `renewal_qualification`
- one review surface only: `outcome_review_bundle`
- one Mercury-owned renewal-qualification path only
- one Mercury-owned outcome-review approval only
- one Mercury-owned expansion-boundary handoff only

The lane reuses already validated Mercury artifacts:

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
- one inquiry package plus verification report
- one reviewer package plus qualification report

It does not authorize a generic customer-success suite, CRM workflow,
account-management platform, channel marketplace, merged shell, ARC
commercial console, or broader Mercury customer-platform claim.

---

## Frozen Renewal Motion

The renewal motion is fixed for this lane:

- `renewal_qualification`

That motion label is part of the contract. If Mercury needs broader renewal
programs, multi-account expansion motions, or generalized customer-success
automation later, that is a new milestone, not an implicit widening of
`v2.59`.

---

## Selected Review Surface

The selected review surface is:

- `outcome_review_bundle`

That surface packages the existing Mercury truth chain for one previously
stabilized account and one renewal decision only. The workflow sentence
remains unchanged:

> Controlled release, rollback, and inquiry evidence for AI-assisted execution
> workflow changes.

---

## Owners

- qualification owner: `mercury-renewal-qualification`
- review owner: `mercury-outcome-review`
- expansion owner: `mercury-expansion-boundary`

Renewal qualification ownership stays inside Mercury. ARC remains the generic
substrate that Mercury consumes; ARC does not become a customer-success,
account-management, or commercial renewal console.

---

## Supported Scope

Supported in `v2.59`:

- one renewal-qualification profile contract
- one renewal-qualification package contract
- one renewal-boundary freeze artifact
- one renewal-qualification manifest
- one outcome-review summary
- one renewal-approval artifact
- one reference-reuse discipline artifact
- one expansion-boundary handoff over the same delivery-continuity,
  selective-account-activation, broader-distribution, reference-distribution,
  controlled-adoption, release-readiness, trust-network, assurance, proof,
  and inquiry chain

Not supported in `v2.59`:

- multiple renewal motions or review surfaces
- a generic customer-success suite, CRM workflow, or account-management
  platform
- channel marketplaces or multi-account renewal programs
- a merged Mercury and ARC-Wall shell
- ARC-side commercial control surfaces
- broader Mercury product-family or universal renewal claims

---

## Canonical Commands

Export the bounded renewal-qualification package and outcome-review bundle:

```bash
cargo run -p arc-mercury -- renewal-qualification export --output target/mercury-renewal-qualification-export
```

Generate the validation package and explicit proceed decision:

```bash
cargo run -p arc-mercury -- renewal-qualification validate --output target/mercury-renewal-qualification-validation
```

These commands remain Mercury-owned wrappers over existing Mercury artifacts.
ARC stays generic; Mercury stays opinionated.
