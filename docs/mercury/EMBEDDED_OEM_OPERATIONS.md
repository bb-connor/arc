# MERCURY Embedded OEM Operations

**Date:** 2026-04-03  
**Milestone:** `v2.48`

---

## Purpose

The embedded OEM lane packages Mercury evidence for one partner reviewer
workbench. This runbook defines how that bundle is staged, acknowledged, and
recovered without widening into a generic SDK program.

---

## Required Bundle Components

Every `embedded-oem export` bundle must include:

- one embedded OEM profile
- one partner SDK manifest
- one assurance-suite package copy
- one governance decision package copy
- one counterparty-review disclosure profile
- one counterparty-review review package
- one counterparty-review investigation package
- one reviewer package
- one qualification report
- one delivery acknowledgement

The partner surface is incomplete if any of those files are missing,
inconsistent, or unresolved.

---

## Operating Boundary

- partner owner: `partner-review-platform-owner`
- Mercury support owner: `mercury-embedded-ops`

The partner owner acknowledges receipt of the bundle and stages it inside the
reviewer workbench. Mercury support owns fail-closed recovery and re-export
when artifact integrity or delivery continuity is lost.

---

## Fail-Closed Rules

The embedded OEM path must fail closed when:

- the partner manifest and embedded OEM profile disagree
- the governance decision package or assurance-suite package is missing
- the counterparty-review package family is incomplete
- the reviewer package or qualification report cannot be matched back to the
  same workflow
- acknowledgement cannot be recorded

Recovery posture:

1. stop partner bundle promotion immediately
2. regenerate the export from the canonical Mercury assurance path
3. require a fresh acknowledgement before the bundle is considered active again

---

## Deferred Operations

This runbook does not authorize:

- multiple partner-specific delivery modes
- broad client-library maintenance
- trust-network witness or publication services
- Chio-Wall companion-product operations

Those remain separate milestones, not hidden responsibilities inside `v2.48`.
