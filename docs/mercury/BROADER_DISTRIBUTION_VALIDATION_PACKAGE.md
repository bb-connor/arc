# MERCURY Broader Distribution Validation Package

**Date:** 2026-04-04  
**Milestone:** `v2.56`

---

## Purpose

`broader-distribution validate` is the canonical close-out command for the
bounded Mercury broader-distribution lane. It generates the governed
qualification bundle, writes the validation report, and emits one explicit
proceed decision instead of implying a generic sales platform, CRM workflow,
channel console, merged shell, or ARC commercial surface.

---

## Command

```bash
cargo run -p arc-mercury -- broader-distribution validate --output target/mercury-broader-distribution-validation
```

---

## Output Layout

```text
target/mercury-broader-distribution-validation/
├── broader-distribution/
│   ├── reference-distribution/
│   ├── qualification-evidence/
│   │   ├── reference-distribution-package.json
│   │   ├── account-motion-freeze.json
│   │   ├── reference-distribution-manifest.json
│   │   ├── reference-claim-discipline-rules.json
│   │   ├── reference-buyer-approval.json
│   │   ├── reference-sales-handoff-brief.json
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
│   ├── broader-distribution-profile.json
│   ├── broader-distribution-package.json
│   ├── broader-distribution-summary.json
│   ├── target-account-freeze.json
│   ├── broader-distribution-manifest.json
│   ├── claim-governance-rules.json
│   ├── selective-account-approval.json
│   └── distribution-handoff-brief.json
├── validation-report.json
└── broader-distribution-decision.json
```

---

## Supported Claim

This package supports one bounded claim only:

> Mercury can proceed with one broader-distribution readiness motion using one
> governed distribution bundle for selective account qualification rooted in
> the validated reference-distribution, controlled-adoption, release-
> readiness, trust-network, assurance, proof, and inquiry stack without
> widening ARC or creating a generic commercial platform.

---

## Non-Claims

This package does not claim:

- multiple broader-distribution motions or surfaces
- a generic sales platform, CRM workflow, channel console, or ARC commercial
  console
- partner marketplaces or multi-segment account programs
- a merged Mercury and ARC-Wall shell
- universal rollout readiness or broad business performance guarantees
