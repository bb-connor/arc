# MERCURY Delivery Continuity

**Date:** 2026-04-04  
**Milestone:** `v2.58`  
**Audience:** product, revenue, delivery, customer evidence, and operators

---

## Purpose

This document freezes the bounded Mercury delivery-continuity lane selected
for `v2.58`.

The lane is intentionally narrow:

- one continuity motion only: `controlled_delivery_continuity`
- one continuity surface only: `outcome_evidence_bundle`
- one Mercury-owned continuity path only
- one Mercury-owned renewal gate only
- one Mercury-owned customer-evidence handoff only

The lane reuses already validated Mercury artifacts:

- one selective-account-activation package
- one activation-scope freeze artifact
- one selective-account-activation manifest
- one claim-containment rules file
- one activation-approval-refresh artifact
- one customer-handoff brief
- one broader-distribution package
- one broader-distribution manifest
- one target-account freeze artifact
- one claim-governance rules file
- one selective-account approval artifact
- one reference-distribution package
- one controlled-adoption package
- one release-readiness package
- one trust-network package
- one assurance-suite package
- one proof package
- one inquiry package plus verification report
- one reviewer package plus qualification report

It does not authorize a generic onboarding suite, CRM workflow, support desk,
channel marketplace, merged shell, Chio commercial console, or broader Mercury
customer-platform claim.

---

## Frozen Continuity Motion

The continuity motion is fixed for this lane:

- `controlled_delivery_continuity`

That motion label is part of the contract. If Mercury needs broader account
portfolio continuity, multi-account service programs, or generalized support
automation later, that is a new milestone, not an implicit widening of
`v2.58`.

---

## Selected Continuity Surface

The selected continuity surface is:

- `outcome_evidence_bundle`

That surface packages the existing Mercury truth chain for one already
activated account and one renewal gate only. The workflow sentence remains
unchanged:

> Controlled release, rollback, and inquiry evidence for AI-assisted execution
> workflow changes.

---

## Owners

- continuity owner: `mercury-delivery-continuity`
- renewal owner: `mercury-renewal-gate`
- evidence owner: `mercury-customer-evidence`

Continuity ownership stays inside Mercury. Chio remains the generic substrate
that Mercury consumes; Chio does not become a customer-success, onboarding, or
commercial continuity console.

---

## Supported Scope

Supported in `v2.58`:

- one delivery-continuity profile contract
- one delivery-continuity package contract
- one account-boundary freeze artifact
- one delivery-continuity manifest
- one outcome-evidence summary
- one renewal-gate artifact
- one delivery-escalation brief
- one customer-evidence handoff over the same selective-account-activation,
  broader-distribution, reference-distribution, controlled-adoption,
  release-readiness, trust-network, assurance, proof, and inquiry chain

Not supported in `v2.58`:

- multiple continuity motions or surfaces
- a generic onboarding suite, CRM workflow, or support desk
- channel marketplaces or multi-account continuity programs
- a merged Mercury and Chio-Wall shell
- Chio-side commercial control surfaces
- broader Mercury product-family or universal account-health claims

---

## Canonical Commands

Export the bounded delivery-continuity package and outcome-evidence bundle:

```bash
cargo run -p chio-mercury -- delivery-continuity export --output target/mercury-delivery-continuity-export
```

Generate the validation package and explicit proceed decision:

```bash
cargo run -p chio-mercury -- delivery-continuity validate --output target/mercury-delivery-continuity-validation
```

These commands remain Mercury-owned wrappers over existing Mercury artifacts.
Chio stays generic; Mercury stays opinionated.
