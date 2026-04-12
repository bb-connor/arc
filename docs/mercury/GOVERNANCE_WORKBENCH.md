# MERCURY Governance Workbench

**Date:** 2026-04-03  
**Audience:** product, engineering, workflow owners, and control teams

---

## Purpose

This document freezes the bounded governance-workbench lane selected for
`v2.46`.

The lane is intentionally narrow:

- one `change_review_release_control` workflow path
- one workflow-owner review package
- one control-team review package
- one fail-closed control-state contract for approval, release, rollback, and
  exception handling

It does not approve a generic governance platform, multiple governance lanes,
or additional downstream connectors.

---

## Selected Workflow Path

The selected governance-workbench path is:

`change_review_release_control`

That path covers governed review of:

- model changes
- prompt changes
- policy changes
- parameter changes
- release changes

The path stays rooted in the same workflow sentence already frozen for
MERCURY:

> Controlled release, rollback, and inquiry evidence for AI-assisted execution
> workflow changes.

---

## Operational Owners

- workflow owner: `mercury-workflow-owner`
- control-team owner: `mercury-control-review`

The workflow owner approves whether a governed change should proceed inside the
bounded release-control workflow. The control-team owner owns bounded review,
exception routing, and fail-closed escalation when package or control-state
claims are incomplete.

---

## Scope Boundary

Supported in `v2.46`:

- one governance-workbench workflow path
- one governance decision package
- one workflow-owner review package
- one control-team review package
- one explicit control-state file for approval, release, rollback, and
  exception posture

Not supported in `v2.46`:

- additional governance workflow breadth
- additional downstream consumer connectors
- generic workflow orchestration
- OMS/EMS or FIX runtime coupling
- OEM packaging and trust-network work

---

## Canonical Commands

Export the bounded governance-workbench package:

```bash
cargo run -p arc-mercury -- governance-workbench export --output target/mercury-governance-workbench-export
```

Generate the validation package and explicit next-step decision:

```bash
cargo run -p arc-mercury -- governance-workbench validate --output target/mercury-governance-workbench-validation
```

These commands must remain wrappers over the existing ARC evidence export plus
MERCURY proof, inquiry, reviewer, and supervised-live qualification artifacts.
