# MERCURY Governance Workbench Operations

**Date:** 2026-04-03  
**Audience:** workflow owners, control teams, and Mercury operators

---

## Operating Model

The governance-workbench lane is a bounded review path for governed change
approval over the same workflow evidence already qualified in MERCURY.

The export path is:

1. generate the supervised-live qualification artifacts
2. derive workflow-owner and control-team inquiry packages from the same proof
   package
3. write one governance control-state file and one governance decision package
4. write the bounded workflow-owner and control-team review packages

If any required artifact is missing or the bounded control state cannot be
generated truthfully, the export must fail closed.

---

## Required Checks

- the output directory is empty before export starts
- the supervised-live proof package verifies successfully before governance
  review artifacts are generated
- workflow-owner and control-team inquiry packages verify successfully
- the governance decision package validates against the bounded schema
- the control-state file names explicit owners and non-empty gate posture

---

## Failure Recovery

- **Missing proof or reviewer artifact:** stop export, regenerate from the
  same supervised-live qualification path, do not handcraft replacements
- **Control-state mismatch:** stop export, correct the bounded approval,
  release, rollback, or exception state, and rerun
- **Review-package validation failure:** regenerate the audience package from
  the same proof and inquiry artifacts; do not widen the schema
- **Owner ambiguity or missing escalation path:** treat the workflow as not
  exportable until one workflow owner and one control-team owner are explicit

---

## Support Boundary

Supported in `v2.46`:

- one `change_review_release_control` workflow path
- one workflow-owner review package
- one control-team review package
- one fail-closed escalation owner

Not supported in `v2.46`:

- multiple governance workflow families
- generic orchestration or ticket-routing systems
- additional downstream connectors
- OEM packaging or embedded runtime ownership
