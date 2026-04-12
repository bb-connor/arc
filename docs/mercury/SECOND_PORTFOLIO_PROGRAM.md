# MERCURY Second Portfolio Program

**Date:** 2026-04-04  
**Milestone:** `v2.62`  
**Audience:** product, revenue, portfolio reuse review, revenue boundary, and operators

---

## Purpose

This document freezes the bounded Mercury second-portfolio-program lane
selected for `v2.62`.

The lane is intentionally narrow:

- one program motion only: `second_portfolio_program`
- one review surface only: `portfolio_reuse_bundle`
- one Mercury-owned second-portfolio-program path only
- one Mercury-owned portfolio-reuse approval only
- one Mercury-owned revenue-boundary-guardrails and second-program-handoff
  path only

The lane reuses already validated Mercury artifacts:

- one portfolio-program package
- one portfolio-program boundary-freeze artifact
- one portfolio-program manifest
- one program-review summary
- one portfolio-approval artifact
- one revenue-operations-guardrails artifact
- one program-handoff artifact
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

It does not authorize a generic portfolio-management suite, account-management
platform, customer-success workflow, revenue operations system, forecasting
stack, billing platform, channel program, merged shell, ARC commercial
console, or broader Mercury multi-program claim.

---

## Frozen Program Motion

The program motion is fixed for this lane:

- `second_portfolio_program`

That motion label is part of the contract. If Mercury needs reusable
multi-program tooling, generalized portfolio management, or broader revenue
operations automation later, that is a new milestone, not an implicit
widening of `v2.62`.

---

## Selected Review Surface

The selected review surface is:

- `portfolio_reuse_bundle`

That surface packages the existing Mercury truth chain for one bounded
adjacent second-program reuse decision only. The workflow sentence remains
unchanged:

> Controlled release, rollback, and inquiry evidence for AI-assisted execution
> workflow changes.

---

## Owners

- program owner: `mercury-second-portfolio-program`
- review owner: `mercury-portfolio-reuse-review`
- revenue-boundary guardrails owner: `mercury-revenue-boundary-guardrails`

Second-portfolio-program ownership stays inside Mercury. ARC remains the
generic substrate that Mercury consumes; ARC does not become a portfolio-
management, account-management, revenue operations, forecasting, billing, or
commercial expansion console.

---

## Supported Scope

Supported in `v2.62`:

- one second-portfolio-program profile contract
- one second-portfolio-program package contract
- one second-portfolio-program boundary-freeze artifact
- one second-portfolio-program manifest
- one portfolio-reuse summary
- one portfolio-reuse approval artifact
- one revenue-boundary-guardrails artifact
- one second-program handoff over the same portfolio-program,
  second-account-expansion, renewal-qualification, delivery-continuity,
  selective-account-activation, broader-distribution, reference-distribution,
  controlled-adoption, release-readiness, trust-network, assurance, proof, and
  inquiry chain

Not supported in `v2.62`:

- multiple program motions or review surfaces
- a generic portfolio-management suite, account-management platform,
  customer-success workflow, or revenue operations system
- forecasting stacks, billing platforms, or channel programs
- a merged Mercury and ARC-Wall shell
- ARC-side commercial control surfaces
- broader Mercury multi-program or universal portfolio claims

---

## Canonical Commands

Export the bounded second-portfolio-program package and portfolio-reuse
bundle:

```bash
cargo run -p arc-mercury -- second-portfolio-program export --output target/mercury-second-portfolio-program-export
```

Generate the validation package and explicit proceed decision:

```bash
cargo run -p arc-mercury -- second-portfolio-program validate --output target/mercury-second-portfolio-program-validation
```

These commands remain Mercury-owned wrappers over existing Mercury artifacts.
ARC stays generic; Mercury stays opinionated.
