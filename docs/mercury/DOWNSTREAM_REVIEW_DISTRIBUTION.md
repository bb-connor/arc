# MERCURY Downstream Review Distribution

**Date:** 2026-04-02  
**Scope:** `v2.45` first downstream-consumer path

---

## Purpose

`v2.45` activates one downstream evidence-consumer path only:

> Case-management review intake over a bounded file-drop package.

This path is chosen because it strengthens review and investigation workflows
without forcing deep runtime coupling or reopening the supervised-live bridge.

---

## Selected Consumer

- **Consumer class:** review / case-management system
- **Profile name:** `case_management_review`
- **Delivery mode:** `file_drop`
- **Destination label:** `case-management-review-drop`
- **Supported command:** `mercury downstream-review export --output ...`

The package must remain rooted in the same MERCURY proof, inquiry, reviewer,
and qualification artifacts already generated for the controlled release,
rollback, and inquiry workflow.

---

## Delivered Artifacts

The downstream package includes:

- one internal assurance package for MERCURY operators and workflow owners
- one external assurance package for downstream review intake
- the canonical reviewer package and qualification report from the supervised-live bridge
- one consumer manifest that tells the case-management system what is being delivered
- one delivery acknowledgement that records the bounded file-drop handoff

The downstream lane is an evidence-distribution path, not a new truth source.
ARC receipts, checkpoints, proof packages, and inquiry packages remain
authoritative.

---

## Ownership

- **Destination owner:** named partner case-management owner
- **Support owner:** `mercury-review-ops`
- **Escalation boundary:** delivery failures fail closed and stay within the
  bounded review-distribution lane

---

## Non-Goals

This milestone does not approve:

- broad archive connector coverage
- surveillance connector programs
- governance workbench breadth
- OMS/EMS, FIX, or other deep runtime integrations
- OEM packaging or trust-network work

Any of those require a later milestone decision.
