# MERCURY Assurance Suite Decision Record

**Date:** 2026-04-03  
**Milestone:** `v2.47`

---

## Decision

`proceed_assurance_suite_only`

Proceed with one bounded assurance-suite reviewer family only.

---

## Approved Scope

- one assurance-suite package family over the existing qualified workflow
- three reviewer populations only: `internal_review`, `auditor_review`, and
  `counterparty_review`
- one disclosure-profile contract, one review-package contract, and one
  investigation-package contract per reviewer population
- one fail-closed reviewer-owner and support-owner boundary

---

## Deferred Scope

- additional reviewer populations
- generic review portal or case-management product breadth
- additional downstream or governance workflow lanes
- OMS/EMS or FIX coupling
- OEM packaging and trust-network work

---

## Rationale

The assurance-suite lane deepens reviewer-facing value after the governance and
downstream lanes are already validated, while still keeping Mercury as an
opinionated evidence product rather than a generic portal or embedded platform.
