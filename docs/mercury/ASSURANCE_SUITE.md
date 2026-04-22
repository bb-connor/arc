# MERCURY Assurance Suite

**Date:** 2026-04-03  
**Audience:** product, engineering, reviewers, and partner teams

---

## Purpose

This document freezes the bounded assurance-suite lane selected for `v2.47`.

The lane is intentionally narrow:

- one assurance-suite package family over the existing governance and
  supervised-live truth artifacts
- three reviewer populations only: `internal_review`, `auditor_review`, and
  `counterparty_review`
- one disclosure-profile contract, one review-package contract, and one
  investigation-package contract per reviewer population
- one fail-closed reviewer-owner and support-owner boundary

It does not approve a generic review portal, additional reviewer programs,
multiple downstream connectors, or OEM packaging.

---

## Selected Reviewer Populations

The selected assurance-suite populations are:

- `internal_review`
- `auditor_review`
- `counterparty_review`

Those populations stay rooted in the same workflow sentence already frozen for
MERCURY:

> Controlled release, rollback, and inquiry evidence for AI-assisted execution
> workflow changes.

Each reviewer population must consume the same underlying proof chain. Mercury
may change disclosure posture per population, but it must not create a second
truth path.

---

## Operational Owners

- reviewer owner: `mercury-assurance-review`
- support owner: `mercury-assurance-ops`

The reviewer owner owns bounded assurance-package generation and reviewer
readiness. The support owner owns fail-closed recovery when any required
qualification, governance, proof, inquiry, or investigation artifact is
missing or inconsistent.

---

## Scope Boundary

Supported in `v2.47`:

- one assurance-suite package family
- one disclosure-profile contract for each selected reviewer population
- one review package for internal, auditor, and counterparty review
- one investigation package for each selected reviewer population
- one fail-closed package root over the same supervised-live qualification and
  governance-workbench artifacts

Not supported in `v2.47`:

- additional reviewer populations
- generic review portal or case-management product breadth
- additional downstream or governance workflow lanes
- OMS/EMS or FIX runtime coupling
- OEM packaging and trust-network work

---

## Canonical Commands

Export the bounded assurance-suite package family:

```bash
cargo run -p chio-mercury -- assurance-suite export --output target/mercury-assurance-suite-export
```

Generate the validation package and explicit next-step decision:

```bash
cargo run -p chio-mercury -- assurance-suite validate --output target/mercury-assurance-suite-validation
```

These commands must remain wrappers over the existing Chio evidence export,
Mercury proof/inquiry packaging, supervised-live qualification artifacts, and
governance-workbench decision package. Chio stays generic; Mercury stays
opinionated.
