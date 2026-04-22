# MERCURY Downstream Review Validation Package

**Date:** 2026-04-02  
**Audience:** engineering, product, partnerships, and review stakeholders

---

## Purpose

The downstream validation package proves that MERCURY can take the same
workflow evidence used in supervised-live qualification and stage it into one
bounded downstream review-consumer lane.

The canonical command is:

```bash
cargo run -p chio-mercury -- downstream-review validate --output target/mercury-downstream-review-validation
```

---

## Package Contents

The generated validation directory contains:

- `downstream-review/qualification/` with the supervised-live qualification corpus
- `downstream-review/assurance/internal-review/` with the internal assurance package
- `downstream-review/assurance/external-review/` with the external assurance package
- `downstream-review/consumer-drop/` with the bounded case-management intake payload
- `validation-report.json` summarizing the validation result
- `expansion-decision.json` recording the explicit next-step boundary

---

## Supported Claim

The validation package supports one narrow claim:

> MERCURY can package the same governed workflow evidence for one downstream
> case-management review intake without redefining Chio truth or widening into
> broader integration programs.

It does not approve additional downstream consumers, governance workbench
scope, OEM packaging, or deep runtime coupling.
