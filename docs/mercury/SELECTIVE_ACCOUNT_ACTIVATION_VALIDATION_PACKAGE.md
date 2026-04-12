# MERCURY Selective Account Activation Validation Package

**Date:** 2026-04-04  
**Milestone:** `v2.57`

---

## Purpose

`selective-account-activation validate` is the canonical close-out command for
the bounded Mercury selective-account-activation lane. It generates the
controlled delivery bundle, writes the validation report, and emits one
explicit proceed decision instead of implying a generic onboarding suite, CRM
workflow, channel marketplace, merged shell, or ARC commercial surface.

---

## Command

```bash
cargo run -p arc-mercury -- selective-account-activation validate --output target/mercury-selective-account-activation-validation
```

---

## Output Layout

```text
target/mercury-selective-account-activation-validation/
├── selective-account-activation/
│   ├── broader-distribution/
│   ├── activation-evidence/
│   │   ├── broader-distribution-package.json
│   │   ├── target-account-freeze.json
│   │   ├── broader-distribution-manifest.json
│   │   ├── claim-governance-rules.json
│   │   ├── selective-account-approval.json
│   │   ├── distribution-handoff-brief.json
│   │   ├── reference-distribution-package.json
│   │   ├── controlled-adoption-package.json
│   │   ├── release-readiness-package.json
│   │   ├── trust-network-package.json
│   │   ├── assurance-suite-package.json
│   │   ├── proof-package.json
│   │   ├── inquiry-package.json
│   │   ├── inquiry-verification.json
│   │   ├── reviewer-package.json
│   │   └── qualification-report.json
│   ├── selective-account-activation-profile.json
│   ├── selective-account-activation-package.json
│   ├── selective-account-activation-summary.json
│   ├── activation-scope-freeze.json
│   ├── selective-account-activation-manifest.json
│   ├── claim-containment-rules.json
│   ├── activation-approval-refresh.json
│   └── customer-handoff-brief.json
├── validation-report.json
└── selective-account-activation-decision.json
```

---

## Supported Claim

This package supports one bounded claim only:

> Mercury can proceed with one selective-account activation motion using one
> controlled delivery bundle rooted in the validated broader-distribution,
> reference-distribution, controlled-adoption, release-readiness, trust-
> network, assurance, proof, and inquiry stack without widening ARC or
> creating a generic onboarding platform.

---

## Non-Claims

This package does not claim:

- multiple activation motions or delivery surfaces
- a generic onboarding suite, CRM workflow, or channel marketplace
- partner marketplaces or multi-segment activation programs
- a merged Mercury and ARC-Wall shell
- universal rollout readiness or broad business performance guarantees
