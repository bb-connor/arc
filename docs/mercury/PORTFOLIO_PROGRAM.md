# MERCURY Portfolio Program

**Date:** 2026-04-04  
**Milestone:** `v2.61`  
**Audience:** product, revenue, portfolio review, revenue operations, and operators

---

## Purpose

This document freezes the bounded Mercury portfolio-program lane selected for
`v2.61`.

The lane is intentionally narrow:

- one program motion only: `portfolio_program`
- one review surface only: `program_review_bundle`
- one Mercury-owned portfolio-program path only
- one Mercury-owned program-review approval only
- one Mercury-owned revenue-operations-guardrails and program-handoff path only

The lane reuses already validated Mercury artifacts:

- one second-account-expansion package
- one second-account portfolio-boundary freeze artifact
- one second-account-expansion manifest
- one second-account portfolio-review summary
- one second-account expansion-approval artifact
- one second-account reuse-governance artifact
- one second-account handoff artifact
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

It does not authorize a generic account-management suite, CRM workflow,
customer-success platform, revenue operations system, forecasting stack,
billing platform, channel program, merged shell, ARC commercial console, or
broader Mercury portfolio-management claim.

---

## Frozen Program Motion

The program motion is fixed for this lane:

- `portfolio_program`

That motion label is part of the contract. If Mercury needs reusable
multi-program tooling, generalized portfolio management, or broader revenue
operations automation later, that is a new milestone, not an implicit widening
of `v2.61`.

---

## Selected Review Surface

The selected review surface is:

- `program_review_bundle`

That surface packages the existing Mercury truth chain for one bounded
portfolio-program decision only. The workflow sentence remains unchanged:

> Controlled release, rollback, and inquiry evidence for AI-assisted execution
> workflow changes.

---

## Owners

- program owner: `mercury-portfolio-program`
- review owner: `mercury-program-review`
- revenue-operations guardrails owner: `mercury-revenue-ops-guardrails`

Portfolio-program ownership stays inside Mercury. ARC remains the generic
substrate that Mercury consumes; ARC does not become an account-management,
revenue operations, forecasting, billing, or commercial expansion console.

---

## Supported Scope

Supported in `v2.61`:

- one portfolio-program profile contract
- one portfolio-program package contract
- one portfolio-program boundary-freeze artifact
- one portfolio-program manifest
- one program-review summary
- one portfolio-approval artifact
- one revenue-operations-guardrails artifact
- one program handoff over the same second-account-expansion,
  renewal-qualification, delivery-continuity, selective-account-activation,
  broader-distribution, reference-distribution, controlled-adoption,
  release-readiness, trust-network, assurance, proof, and inquiry chain

Not supported in `v2.61`:

- multiple program motions or review surfaces
- a generic account-management suite, CRM workflow, customer-success platform,
  or revenue operations system
- forecasting stacks, billing platforms, or channel programs
- a merged Mercury and ARC-Wall shell
- ARC-side commercial control surfaces
- broader Mercury portfolio-management or universal multi-account claims

---

## Canonical Commands

Export the bounded portfolio-program package and program-review bundle:

```bash
cargo run -p arc-mercury -- portfolio-program export --output target/mercury-portfolio-program-export
```

Generate the validation package and explicit proceed decision:

```bash
cargo run -p arc-mercury -- portfolio-program validate --output target/mercury-portfolio-program-validation
```

These commands remain Mercury-owned wrappers over existing Mercury artifacts.
ARC stays generic; Mercury stays opinionated.
