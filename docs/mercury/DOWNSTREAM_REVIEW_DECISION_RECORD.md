# MERCURY Downstream Review Decision Record

**Date:** 2026-04-02  
**Milestone:** `v2.45`

---

## Decision

`proceed_case_management_only`

Proceed with one bounded downstream case-management review-consumer lane.

---

## Approved Scope

- one `case_management_review` consumer profile
- one `file_drop` delivery contract
- one internal assurance package
- one external assurance package
- one explicit delivery acknowledgement and support boundary

---

## Deferred Scope

- additional archive connectors
- surveillance connectors
- governance workbench expansion
- OMS/EMS or FIX runtime coupling
- OEM packaging and trust-network work

---

## Rationale

The case-management review lane is the narrowest credible downstream expansion
that strengthens buyer review workflows while preserving MERCURY as an
evidence layer on ARC rather than a generic connector hub.
