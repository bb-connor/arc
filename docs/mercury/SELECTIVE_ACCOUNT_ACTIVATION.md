# MERCURY Selective Account Activation

**Date:** 2026-04-04  
**Milestone:** `v2.57`  
**Audience:** product, revenue, delivery, and operators

---

## Purpose

This document freezes the bounded Mercury selective-account-activation lane
selected for `v2.57`.

The lane is intentionally narrow:

- one activation motion only: `selective_account_activation`
- one delivery surface only: `controlled_delivery_bundle`
- one Mercury-owned activation path only
- one Mercury-owned approval-refresh gate only
- one Mercury-owned customer handoff only

The lane reuses already validated Mercury artifacts:

- one broader-distribution package
- one target-account freeze artifact
- one broader-distribution manifest
- one claim-governance rules file
- one selective-account approval artifact
- one distribution-handoff brief
- one reference-distribution package
- one controlled-adoption package
- one release-readiness package
- one trust-network package
- one assurance-suite package
- one proof package
- one inquiry package plus verification report
- one reviewer package plus qualification report

It does not authorize a generic onboarding suite, CRM workflow, channel
marketplace, merged shell, ARC commercial console, or broader Mercury product-
family claim.

---

## Frozen Activation Motion

The activation motion is fixed for this lane:

- `selective_account_activation`

That motion label is part of the contract. If Mercury needs multiple account
segments, onboarding programs, or delivery routes later, that is a new
milestone, not an implicit widening of `v2.57`.

---

## Selected Delivery Surface

The selected delivery surface is:

- `controlled_delivery_bundle`

That surface packages the existing Mercury truth chain for one bounded
selective-account activation motion. The workflow sentence remains unchanged:

> Controlled release, rollback, and inquiry evidence for AI-assisted execution
> workflow changes.

---

## Owners

- activation owner: `mercury-selective-account-activation`
- approval owner: `mercury-activation-approval`
- delivery owner: `mercury-controlled-delivery`

Delivery ownership stays inside Mercury. ARC remains the generic substrate
that Mercury consumes; ARC does not become an onboarding or commercial
activation console.

---

## Supported Scope

Supported in `v2.57`:

- one selective-account-activation profile contract
- one selective-account-activation package contract
- one activation-scope freeze artifact
- one selective-account-activation manifest
- one claim-containment rules file
- one activation-approval-refresh artifact
- one customer-handoff brief over the same broader-distribution, reference-
  distribution, controlled-adoption, release-readiness, trust-network,
  assurance, proof, and inquiry chain

Not supported in `v2.57`:

- multiple activation motions or delivery surfaces
- a generic onboarding suite, CRM workflow, or channel marketplace
- partner marketplaces or multi-segment activation programs
- a merged Mercury and ARC-Wall shell
- ARC-side commercial control surfaces
- broader Mercury product-family or universal rollout claims

---

## Canonical Commands

Export the bounded selective-account-activation package and controlled delivery
bundle:

```bash
cargo run -p arc-mercury -- selective-account-activation export --output target/mercury-selective-account-activation-export
```

Generate the validation package and explicit proceed decision:

```bash
cargo run -p arc-mercury -- selective-account-activation validate --output target/mercury-selective-account-activation-validation
```

These commands remain Mercury-owned wrappers over existing Mercury artifacts.
ARC stays generic; Mercury stays opinionated.
