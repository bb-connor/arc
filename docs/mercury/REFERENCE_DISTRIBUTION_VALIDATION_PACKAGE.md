# MERCURY Reference Distribution Validation Package

**Date:** 2026-04-03  
**Milestone:** `v2.55`

---

## Purpose

`reference-distribution validate` is the canonical close-out command for the
bounded Mercury reference-distribution lane. It generates the landed-account
bundle, writes the validation report, and emits one explicit proceed decision
instead of implying a generic sales platform, CRM workflow, merged shell, or
Chio commercial surface.

---

## Command

```bash
cargo run -p chio-mercury -- reference-distribution validate --output target/mercury-reference-distribution-validation
```

---

## Output Layout

```text
target/mercury-reference-distribution-validation/
├── reference-distribution/
│   ├── controlled-adoption/
│   ├── reference-evidence/
│   │   ├── controlled-adoption-package.json
│   │   ├── renewal-evidence-manifest.json
│   │   ├── renewal-acknowledgement.json
│   │   ├── reference-readiness-brief.json
│   │   ├── release-readiness-package.json
│   │   ├── trust-network-package.json
│   │   ├── assurance-suite-package.json
│   │   ├── proof-package.json
│   │   ├── inquiry-package.json
│   │   ├── inquiry-verification.json
│   │   ├── reviewer-package.json
│   │   └── qualification-report.json
│   ├── reference-distribution-profile.json
│   ├── reference-distribution-package.json
│   ├── reference-distribution-summary.json
│   ├── account-motion-freeze.json
│   ├── reference-distribution-manifest.json
│   ├── claim-discipline-rules.json
│   ├── buyer-reference-approval.json
│   └── sales-handoff-brief.json
├── validation-report.json
└── expansion-decision.json
```

---

## Supported Claim

This package supports one bounded claim only:

> Mercury can proceed with one landed-account expansion motion using one
> approved reference bundle rooted in the validated controlled-adoption,
> release-readiness, trust-network, assurance, proof, and inquiry stack
> without widening Chio or creating a generic sales platform.

---

## Non-Claims

This package does not claim:

- multiple landed-account motions or broader distribution surfaces
- a generic sales platform, CRM workflow, or Chio commercial console
- a merged Mercury and Chio-Wall shell
- universal rollout readiness or broad business performance guarantees
