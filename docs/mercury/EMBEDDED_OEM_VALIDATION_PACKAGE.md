# MERCURY Embedded OEM Validation Package

**Date:** 2026-04-03  
**Milestone:** `v2.48`

---

## Purpose

`embedded-oem validate` is the canonical close-out command for the bounded
embedded OEM lane. It generates the OEM bundle, writes the validation report,
and emits one explicit expansion decision instead of implying a broad SDK or
partner-platform strategy.

---

## Command

```bash
cargo run -p arc-mercury -- embedded-oem validate --output target/mercury-embedded-oem-validation
```

---

## Output Layout

```text
target/mercury-embedded-oem-validation/
├── embedded-oem/
│   ├── assurance-suite/
│   ├── embedded-oem-profile.json
│   ├── embedded-oem-package.json
│   ├── embedded-oem-summary.json
│   ├── partner-sdk-manifest.json
│   └── partner-sdk-bundle/
│       ├── assurance-suite-package.json
│       ├── governance-decision-package.json
│       ├── disclosure-profile.json
│       ├── review-package.json
│       ├── investigation-package.json
│       ├── reviewer-package.json
│       ├── qualification-report.json
│       └── delivery-acknowledgement.json
├── validation-report.json
└── expansion-decision.json
```

---

## Supported Claim

This package supports one bounded claim only:

> Mercury can package one counterparty-review bundle for one
> `reviewer_workbench_embed` partner surface through one
> `signed_artifact_bundle` manifest contract without widening into a generic
> SDK platform.

---

## Non-Claims

This package does not claim:

- multi-partner OEM breadth
- generic SDK parity
- trust-network interoperability services
- ARC-Wall readiness
