# MERCURY Second-Account Expansion

**Date:** 2026-04-04  
**Milestone:** `v2.60`  
**Audience:** product, revenue, portfolio review, reuse governance, and operators

---

## Purpose

This document freezes the bounded Mercury second-account-expansion lane
selected for `v2.60`.

The lane is intentionally narrow:

- one expansion motion only: `second_account_expansion`
- one review surface only: `portfolio_review_bundle`
- one Mercury-owned second-account-expansion path only
- one Mercury-owned portfolio-review approval only
- one Mercury-owned reuse-governance and second-account handoff only

The lane reuses already validated Mercury artifacts:

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
- one inquiry package plus verification report
- one reviewer package plus qualification report

It does not authorize a generic customer-success suite, CRM workflow,
account-management platform, revenue operations system, channel marketplace,
merged shell, Chio commercial console, or broader Mercury account-portfolio
claim.

---

## Frozen Expansion Motion

The expansion motion is fixed for this lane:

- `second_account_expansion`

That motion label is part of the contract. If Mercury needs broader
multi-account programs, reusable portfolio tooling, or generalized
account-management automation later, that is a new milestone, not an implicit
widening of `v2.60`.

---

## Selected Review Surface

The selected review surface is:

- `portfolio_review_bundle`

That surface packages the existing Mercury truth chain for one renewed account
and one follow-on account decision only. The workflow sentence remains
unchanged:

> Controlled release, rollback, and inquiry evidence for AI-assisted execution
> workflow changes.

---

## Owners

- expansion owner: `mercury-second-account-expansion`
- review owner: `mercury-portfolio-review`
- reuse governance owner: `mercury-reuse-governance`

Second-account expansion ownership stays inside Mercury. Chio remains the
generic substrate that Mercury consumes; Chio does not become a customer-
success, account-management, revenue operations, or commercial expansion
console.

---

## Supported Scope

Supported in `v2.60`:

- one second-account-expansion profile contract
- one second-account-expansion package contract
- one portfolio-boundary freeze artifact
- one second-account-expansion manifest
- one portfolio-review summary
- one expansion-approval artifact
- one reuse-governance artifact
- one second-account handoff over the same renewal-qualification,
  delivery-continuity, selective-account-activation, broader-distribution,
  reference-distribution, controlled-adoption, release-readiness,
  trust-network, assurance, proof, and inquiry chain

Not supported in `v2.60`:

- multiple expansion motions or review surfaces
- a generic customer-success suite, CRM workflow, account-management
  platform, or revenue operations system
- multi-account portfolio programs or channel marketplaces
- a merged Mercury and Chio-Wall shell
- Chio-side commercial control surfaces
- broader Mercury portfolio-management or universal expansion claims

---

## Canonical Commands

Export the bounded second-account-expansion package and portfolio-review
bundle:

```bash
cargo run -p chio-mercury -- second-account-expansion export --output target/mercury-second-account-expansion-export
```

Generate the validation package and explicit proceed decision:

```bash
cargo run -p chio-mercury -- second-account-expansion validate --output target/mercury-second-account-expansion-validation
```

These commands remain Mercury-owned wrappers over existing Mercury artifacts.
Chio stays generic; Mercury stays opinionated.
