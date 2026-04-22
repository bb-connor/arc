# MERCURY Second-Account Expansion Validation Package

**Date:** 2026-04-04  
**Milestone:** `v2.60`

---

## Purpose

This package validates that Mercury can qualify one bounded
second-account-expansion lane without widening into a generic account or
portfolio platform.

The supported claim is narrow:

> Mercury can qualify one second-account expansion through one
> `second_account_expansion` motion using one `portfolio_review_bundle`
> rooted in the validated renewal-qualification chain.

---

## Generation Command

```bash
cargo run -p chio-mercury -- second-account-expansion validate --output target/mercury-second-account-expansion-validation
```

---

## Expected Layout

- `second-account-expansion/second-account-expansion-package.json`
- `second-account-expansion/portfolio-boundary-freeze.json`
- `second-account-expansion/second-account-expansion-manifest.json`
- `second-account-expansion/portfolio-review-summary.json`
- `second-account-expansion/expansion-approval.json`
- `second-account-expansion/reuse-governance.json`
- `second-account-expansion/second-account-handoff.json`
- `validation-report.json`
- `second-account-expansion-decision.json`

The validation corpus also includes the copied renewal and prior Mercury
evidence chain under `second-account-expansion/expansion-evidence/`.

---

## Decision Standard

Proceed only if all of the following are true:

- one expansion motion only: `second_account_expansion`
- one review surface only: `portfolio_review_bundle`
- one Mercury-owned approval and reuse-governance path only
- no implication of generic customer-success, CRM, account management,
  revenue operations, or Chio commercial tooling

Anything broader requires a new milestone.
