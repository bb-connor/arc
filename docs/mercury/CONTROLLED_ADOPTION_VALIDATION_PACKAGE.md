# MERCURY Controlled Adoption Validation Package

**Date:** 2026-04-03  
**Milestone:** `v2.54`

---

## Purpose

`controlled-adoption validate` is the canonical close-out command for the
bounded Mercury controlled-adoption lane. It generates the adoption package,
writes the validation report, and emits one explicit scale decision instead of
implying a generic ARC renewal console, merged shell, or new Mercury product
surface.

---

## Command

```bash
cargo run -p arc-mercury -- controlled-adoption validate --output target/mercury-controlled-adoption-validation
```

---

## Output Layout

```text
target/mercury-controlled-adoption-validation/
├── controlled-adoption/
│   ├── release-readiness/
│   ├── adoption-evidence/
│   │   ├── release-readiness-package.json
│   │   ├── trust-network-package.json
│   │   ├── assurance-suite-package.json
│   │   ├── proof-package.json
│   │   ├── inquiry-package.json
│   │   ├── inquiry-verification.json
│   │   ├── reviewer-package.json
│   │   └── qualification-report.json
│   ├── controlled-adoption-profile.json
│   ├── controlled-adoption-package.json
│   ├── controlled-adoption-summary.json
│   ├── customer-success-checklist.json
│   ├── renewal-evidence-manifest.json
│   ├── renewal-acknowledgement.json
│   ├── reference-readiness-brief.json
│   └── support-escalation-manifest.json
├── validation-report.json
└── expansion-decision.json
```

---

## Supported Claim

This package supports one bounded claim only:

> Mercury can scale one controlled-adoption lane for
> `design_partner_renewal` over one `renewal_reference_bundle` built from the
> existing release-readiness, trust-network, assurance, proof, and inquiry
> stack without widening ARC or creating a new Mercury surface family.

---

## Non-Claims

This package does not claim:

- additional adoption cohorts or renewal surfaces
- a generic ARC renewal console
- a merged Mercury and ARC-Wall shell
- broader Mercury product-family scope
- cross-product packaging unification
