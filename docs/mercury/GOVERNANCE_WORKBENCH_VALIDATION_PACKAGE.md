# MERCURY Governance Workbench Validation Package

**Date:** 2026-04-03  
**Audience:** engineering, product, workflow owners, and control-team reviewers

---

## Purpose

The governance validation package proves that MERCURY can package one bounded
governance-workbench workflow over the same Chio and MERCURY truth artifacts
already used for supervised-live qualification.

The canonical command is:

```bash
cargo run -p chio-mercury -- governance-workbench validate --output target/mercury-governance-workbench-validation
```

---

## Package Contents

The generated validation directory contains:

- `governance-workbench/qualification/` with the supervised-live qualification
  corpus
- `governance-workbench/governance-control-state.json` with the bounded gate
  and escalation state
- `governance-workbench/governance-decision-package.json` with the selected
  governance-workbench contract
- `governance-workbench/governance-reviews/workflow-owner/` with the
  workflow-owner inquiry and review package
- `governance-workbench/governance-reviews/control-team/` with the
  control-team inquiry and review package
- `validation-report.json` summarizing the validation result
- `expansion-decision.json` recording the explicit next-step boundary

---

## Supported Claim

The validation package supports one narrow claim:

> MERCURY can package one bounded governance-workbench change-review and
> release-control workflow without redefining Chio truth or widening into
> generic orchestration.

It does not approve additional governance workflow breadth, additional
downstream connectors, OEM packaging, or deep runtime coupling.
