# MERCURY Governance Workbench Decision Record

**Date:** 2026-04-03  
**Milestone:** `v2.46`

---

## Decision

`proceed_governance_workbench_only`

Proceed with one bounded governance-workbench change-review and release-control
workflow only.

---

## Approved Scope

- one `change_review_release_control` workflow path
- one workflow-owner review package
- one control-team review package
- one explicit control-state file for approval, release, rollback, and
  exception posture
- one fail-closed escalation path owned by the control team

---

## Deferred Scope

- additional governance workflow breadth
- additional downstream consumer connectors
- OMS/EMS or FIX coupling
- OEM packaging and trust-network work
- generic workflow orchestration

---

## Rationale

The governance-workbench lane deepens buyer workflow value after the first
downstream validation without collapsing Mercury into connector sprawl or a
generic workflow engine. The milestone therefore closes with one explicit
governance path, one operating boundary, and one next-step decision.
