# MERCURY Broader Distribution

**Date:** 2026-04-04  
**Milestone:** `v2.56`  
**Audience:** product, partnerships, revenue, and operators

---

## Purpose

This document freezes the bounded Mercury broader-distribution lane selected
for `v2.56`.

The lane is intentionally narrow:

- one distribution motion only: `selective_account_qualification`
- one distribution surface only: `governed_distribution_bundle`
- one Mercury-owned qualification path only
- one Mercury-owned approval gate only
- one Mercury-owned distribution handoff only

The lane reuses already validated Mercury artifacts:

- one reference-distribution package
- one account-motion freeze artifact
- one reference-distribution manifest
- one claim-discipline rules file
- one buyer-reference approval artifact
- one sales-handoff brief
- one controlled-adoption package
- one renewal-evidence manifest and acknowledgement
- one reference-readiness brief
- one release-readiness package
- one trust-network package
- one assurance-suite package
- one proof package
- one inquiry package plus verification report
- one reviewer package plus qualification report

It does not authorize a generic sales platform, CRM workflow, channel
marketplace, merged shell, ARC commercial console, or broader Mercury product-
family claim.

---

## Frozen Distribution Motion

The distribution motion is fixed for this lane:

- `selective_account_qualification`

That motion label is part of the contract. If Mercury needs multiple account
segments, partner programs, or route-specific motions later, that is a new
milestone, not an implicit widening of `v2.56`.

---

## Selected Distribution Surface

The selected distribution surface is:

- `governed_distribution_bundle`

That surface packages the existing Mercury truth chain for one bounded
selective account-qualification motion. The workflow sentence remains
unchanged:

> Controlled release, rollback, and inquiry evidence for AI-assisted execution
> workflow changes.

---

## Owners

- qualification owner: `mercury-account-qualification`
- approval owner: `mercury-broader-distribution-approval`
- distribution owner: `mercury-broader-distribution`

Distribution ownership stays inside Mercury. ARC remains the generic substrate
that Mercury consumes; ARC does not become a commercial qualification console.

---

## Supported Scope

Supported in `v2.56`:

- one broader-distribution profile contract
- one broader-distribution package contract
- one target-account freeze artifact
- one broader-distribution manifest
- one claim-governance rules file
- one selective-account approval artifact
- one distribution-handoff brief over the same reference-distribution,
  controlled-adoption, release-readiness, trust-network, assurance, proof,
  and inquiry chain

Not supported in `v2.56`:

- multiple broader-distribution motions or surfaces
- a generic sales platform, CRM, or channel console
- partner marketplaces or multi-segment campaign tooling
- a merged Mercury and ARC-Wall shell
- ARC-side commercial control surfaces
- broader Mercury product-family or universal rollout claims

---

## Canonical Commands

Export the bounded broader-distribution package and governed qualification
bundle:

```bash
cargo run -p arc-mercury -- broader-distribution export --output target/mercury-broader-distribution-export
```

Generate the validation package and explicit proceed decision:

```bash
cargo run -p arc-mercury -- broader-distribution validate --output target/mercury-broader-distribution-validation
```

These commands remain Mercury-owned wrappers over existing Mercury artifacts.
ARC stays generic; Mercury stays opinionated.
