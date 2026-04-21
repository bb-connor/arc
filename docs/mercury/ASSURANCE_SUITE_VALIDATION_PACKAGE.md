# MERCURY Assurance Suite Validation Package

**Date:** 2026-04-03  
**Audience:** engineering, product, reviewer owners, auditors, and partner reviewers

---

## Purpose

The assurance validation package proves that MERCURY can package one bounded
assurance-suite lane over the same Chio and MERCURY truth artifacts already
used for supervised-live qualification and governance review.

The canonical command is:

```bash
cargo run -p chio-mercury -- assurance-suite validate --output target/mercury-assurance-suite-validation
```

---

## Package Contents

The generated validation directory contains:

- `assurance-suite/governance-workbench/` with the bounded governance lane and
  supervised-live qualification corpus
- `assurance-suite/reviewer-populations/internal-review/` with the internal
  disclosure profile, review package, inquiry, verification, and investigation
  package
- `assurance-suite/reviewer-populations/auditor-review/` with the auditor
  disclosure profile, review package, inquiry, verification, and investigation
  package
- `assurance-suite/reviewer-populations/counterparty-review/` with the
  counterparty disclosure profile, review package, inquiry, verification, and
  investigation package
- `assurance-suite/assurance-suite-package.json` with the bounded reviewer
  family contract
- `validation-report.json` summarizing the validation result
- `expansion-decision.json` recording the explicit next-step boundary

---

## Supported Claim

The validation package supports one narrow claim:

> MERCURY can package one bounded assurance-suite reviewer family for
> internal, auditor, and counterparty review without redefining Chio truth or
> widening into a generic review portal.

It does not approve additional reviewer populations, additional downstream or
governance lanes, OEM packaging, trust-network work, or deep runtime coupling.
