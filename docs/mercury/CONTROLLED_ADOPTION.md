# MERCURY Controlled Adoption

**Date:** 2026-04-03  
**Milestone:** `v2.54`  
**Audience:** product, customer success, partnerships, and operators

---

## Purpose

This document freezes the bounded Mercury controlled-adoption lane selected
for `v2.54`.

The lane is intentionally narrow:

- one adoption cohort only: `design_partner_renewal`
- one adoption surface only: `renewal_reference_bundle`
- one Mercury-owned customer-success path only
- one Mercury-owned reference-readiness path only
- one Mercury-owned support-escalation path only

The lane reuses already validated Mercury artifacts:

- one release-readiness package
- one trust-network package
- one assurance-suite package
- one proof package
- one inquiry package plus verification report
- one reviewer package plus qualification report

It does not authorize a generic ARC renewal console, a merged Mercury and
ARC-Wall shell, additional adoption cohorts, or a new Mercury product line.

---

## Frozen Cohort

The adoption cohort is fixed for this lane:

- `design_partner_renewal`

That cohort label is part of the contract. If Mercury needs additional
post-launch cohorts later, that is a new milestone, not an implicit widening
of `v2.54`.

---

## Selected Adoption Surface

The selected adoption surface is:

- `renewal_reference_bundle`

That surface packages the existing Mercury truth chain for one bounded
renewal and reference-readiness motion. The workflow sentence remains
unchanged:

> Controlled release, rollback, and inquiry evidence for AI-assisted execution
> workflow changes.

---

## Owners

- customer success owner: `mercury-customer-success`
- reference owner: `mercury-reference-program`
- support owner: `mercury-adoption-ops`

Adoption ownership stays inside Mercury. ARC remains the generic substrate
that Mercury consumes; ARC does not become the renewal or reference-readiness
console.

---

## Supported Scope

Supported in `v2.54`:

- one controlled-adoption profile contract
- one controlled-adoption package contract
- one customer-success checklist
- one renewal-evidence manifest and acknowledgement path
- one reference-readiness brief
- one support-escalation manifest over the same release-readiness, trust-
  network, assurance, proof, and inquiry chain

Not supported in `v2.54`:

- additional adoption cohorts or renewal surfaces
- a generic ARC renewal console or merged shell
- broader Mercury product-family claims
- cross-product packaging unification
- new runtime coupling or generic customer-success tooling

---

## Canonical Commands

Export the bounded controlled-adoption package and renewal evidence bundle:

```bash
cargo run -p arc-mercury -- controlled-adoption export --output target/mercury-controlled-adoption-export
```

Generate the validation package and explicit scale decision:

```bash
cargo run -p arc-mercury -- controlled-adoption validate --output target/mercury-controlled-adoption-validation
```

These commands remain Mercury-owned wrappers over existing Mercury artifacts.
ARC stays generic; Mercury stays opinionated.
