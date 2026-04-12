# MERCURY Portfolio Program Validation Package

**Date:** 2026-04-04  
**Milestone:** `v2.61`

---

## Purpose

This package validates that Mercury can qualify one bounded portfolio-program
lane without widening into a generic account-management or revenue-operations
platform.

The supported claim is narrow:

> Mercury can qualify one bounded portfolio program through one
> `portfolio_program` motion using one `program_review_bundle` rooted in the
> validated second-account-expansion chain.

---

## Generation Command

```bash
cargo run -p arc-mercury -- portfolio-program validate --output target/mercury-portfolio-program-validation
```

---

## Expected Layout

- `portfolio-program/portfolio-program-package.json`
- `portfolio-program/portfolio-program-boundary-freeze.json`
- `portfolio-program/portfolio-program-manifest.json`
- `portfolio-program/program-review-summary.json`
- `portfolio-program/portfolio-approval.json`
- `portfolio-program/revenue-operations-guardrails.json`
- `portfolio-program/program-handoff.json`
- `validation-report.json`
- `portfolio-program-decision.json`

The validation corpus also includes the copied second-account-expansion and
prior Mercury evidence chain under `portfolio-program/portfolio-evidence/`.

---

## Decision Standard

Proceed only if all of the following are true:

- one program motion only: `portfolio_program`
- one review surface only: `program_review_bundle`
- one Mercury-owned approval and revenue-operations-guardrails path only
- no implication of generic account management, customer success, revenue
  operations, forecasting, billing, channel tooling, or ARC commercial
  behavior

Anything broader requires a new milestone.
