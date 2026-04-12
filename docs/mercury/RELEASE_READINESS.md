# MERCURY Release Readiness

**Date:** 2026-04-03  
**Milestone:** `v2.53`  
**Audience:** product, partnerships, release operators, and reviewers

---

## Purpose

This document freezes the bounded Mercury release-readiness lane selected for
`v2.53`.

The lane is intentionally narrow:

- one Mercury release-readiness package family only
- one audience set only: `reviewer`, `partner`, and `operator`
- one delivery surface only: `signed_partner_review_bundle`
- one operator-owned release and escalation path only
- one partner-delivery acknowledgement boundary only
- one Mercury support-owner handoff path only

The package reuses already validated Mercury artifacts:

- one proof package
- one inquiry package plus verification report
- one assurance-suite package
- one trust-network package
- one reviewer package plus qualification report

It does not authorize a generic ARC release console, a merged Mercury and
ARC-Wall shell, additional partner-delivery surfaces, or a new Mercury product
line.

---

## Frozen Audience Set

The audience set is fixed for this lane:

- `reviewer`: validates the bounded release evidence package
- `partner`: receives one signed delivery bundle for controlled adoption
- `operator`: owns release checks, escalation, and support handoff

Those audience labels are part of the contract. If Mercury needs more
audiences later, that is a new milestone, not an implicit widening of `v2.53`.

---

## Selected Delivery Surface

The selected delivery surface is:

- `signed_partner_review_bundle`

That surface packages existing Mercury truth artifacts for one bounded partner
delivery lane. It does not create a second truth path. The workflow sentence
remains unchanged:

> Controlled release, rollback, and inquiry evidence for AI-assisted execution
> workflow changes.

---

## Owners

- release owner: `mercury-release-manager`
- partner owner: `mercury-partner-delivery`
- support owner: `mercury-release-ops`

Release ownership stays inside Mercury. ARC remains the generic substrate that
Mercury consumes; ARC does not become the release-readiness console.

---

## Supported Scope

Supported in `v2.53`:

- one release-readiness profile contract
- one release-readiness package contract
- one partner-delivery manifest and acknowledgement path
- one operator release checklist
- one escalation manifest
- one support handoff over the same proof, inquiry, assurance, and trust-
  network chain

Not supported in `v2.53`:

- additional partner-delivery surfaces
- a generic ARC release console or merged shell
- new Mercury feature lanes or product lines
- widened trust-network sponsor breadth
- ARC-Wall or cross-product packaging unification

---

## Canonical Commands

Export the bounded release-readiness package and partner-delivery bundle:

```bash
cargo run -p arc-mercury -- release-readiness export --output target/mercury-release-readiness-export
```

Generate the validation package and explicit launch decision:

```bash
cargo run -p arc-mercury -- release-readiness validate --output target/mercury-release-readiness-validation
```

These commands must remain Mercury-owned wrappers over existing Mercury
artifacts. ARC stays generic; Mercury stays opinionated.
