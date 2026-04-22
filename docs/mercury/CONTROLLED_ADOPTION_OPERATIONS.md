# MERCURY Controlled Adoption Operations

**Date:** 2026-04-03  
**Milestone:** `v2.54`

---

## Purpose

The controlled-adoption lane packages one bounded Mercury renewal and
reference-readiness motion while preserving the same release-readiness truth
chain. This runbook defines the minimum artifact set, customer-success checks,
reference boundary, and fail-closed recovery posture for that lane.

---

## Required Bundle Components

Every `controlled-adoption export` bundle must include:

- one controlled-adoption profile
- one controlled-adoption package
- one customer-success checklist
- one renewal-evidence manifest
- one renewal acknowledgement
- one reference-readiness brief
- one support-escalation manifest
- one release-readiness package
- one trust-network package
- one assurance-suite package
- one proof package
- one inquiry package
- one inquiry verification report
- one reviewer package
- one qualification report

The bundle is incomplete if any of those files are missing, inconsistent, or
cannot be matched back to the same workflow.

---

## Operating Boundary

- customer success owner: `mercury-customer-success`
- reference owner: `mercury-reference-program`
- Mercury support owner: `mercury-adoption-ops`

Customer success owns the bounded renewal motion. The reference owner controls
the approved claim. Mercury support owns fail-closed recovery whenever the
bundle contents, acknowledgement, or reference brief become incomplete.

---

## Fail-Closed Rules

The controlled-adoption path must fail closed when:

- the controlled-adoption profile and package disagree on cohort or adoption
  surface
- the renewal-evidence manifest omits release-readiness, trust-network,
  assurance, proof, or inquiry files
- the renewal acknowledgement is missing before reuse
- the reference-readiness brief makes broader claims than the approved one
- the customer-success checklist or support-escalation manifest is missing

Recovery posture:

1. stop renewal or reference use immediately
2. regenerate the controlled-adoption export from the canonical
   release-readiness lane
3. require a fresh acknowledgement before treating the bundle as reusable

---

## Deferred Operations

This runbook does not authorize:

- multiple renewal cohorts
- a generic Chio renewal console
- a merged Mercury and Chio-Wall shell
- broad marketing or reference claims beyond the approved sentence
- new Mercury product-line scope

Those remain separate decisions, not hidden responsibilities inside `v2.54`.
