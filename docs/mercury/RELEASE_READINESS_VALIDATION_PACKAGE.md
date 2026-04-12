# MERCURY Release Readiness Validation Package

**Date:** 2026-04-03  
**Milestone:** `v2.53`

---

## Purpose

`release-readiness validate` is the canonical close-out command for the
bounded Mercury release-readiness lane. It generates the release package,
writes the validation report, and emits one explicit launch decision instead
of implying a generic ARC release console, merged shell, or new Mercury
product line.

---

## Command

```bash
cargo run -p arc-mercury -- release-readiness validate --output target/mercury-release-readiness-validation
```

---

## Output Layout

```text
target/mercury-release-readiness-validation/
├── release-readiness/
│   ├── trust-network/
│   ├── partner-delivery/
│   │   ├── proof-package.json
│   │   ├── inquiry-package.json
│   │   ├── inquiry-verification.json
│   │   ├── assurance-suite-package.json
│   │   ├── trust-network-package.json
│   │   ├── reviewer-package.json
│   │   └── qualification-report.json
│   ├── release-readiness-profile.json
│   ├── release-readiness-package.json
│   ├── release-readiness-summary.json
│   ├── partner-delivery-manifest.json
│   ├── delivery-acknowledgement.json
│   ├── operator-release-checklist.json
│   ├── escalation-manifest.json
│   └── support-handoff.json
├── validation-report.json
└── expansion-decision.json
```

---

## Supported Claim

This package supports one bounded claim only:

> Mercury can launch one release-readiness lane for `reviewer`, `partner`, and
> `operator` audiences over one `signed_partner_review_bundle` built from the
> existing proof, inquiry, assurance, and trust-network stack without widening
> ARC or creating a new Mercury product line.

---

## Non-Claims

This package does not claim:

- additional partner-delivery surfaces
- a generic ARC release console
- a merged Mercury and ARC-Wall shell
- new Mercury feature-family scope
- cross-product packaging unification
