# MERCURY Second Portfolio Program Validation Package

**Date:** 2026-04-04  
**Milestone:** `v2.62`

---

## Purpose

This package validates that Mercury can qualify one bounded second-portfolio-
program lane without widening into a generic portfolio-management or revenue
operations platform.

The supported claim is narrow:

> Mercury can qualify one bounded second portfolio program through one
> `second_portfolio_program` motion using one `portfolio_reuse_bundle` rooted
> in the validated portfolio-program chain.

---

## Generation Command

```bash
cargo run -p chio-mercury -- second-portfolio-program validate --output target/mercury-second-portfolio-program-validation
```

---

## Expected Layout

- `second-portfolio-program/second-portfolio-program-package.json`
- `second-portfolio-program/second-portfolio-program-boundary-freeze.json`
- `second-portfolio-program/second-portfolio-program-manifest.json`
- `second-portfolio-program/portfolio-reuse-summary.json`
- `second-portfolio-program/portfolio-reuse-approval.json`
- `second-portfolio-program/revenue-boundary-guardrails.json`
- `second-portfolio-program/second-program-handoff.json`
- `validation-report.json`
- `second-portfolio-program-decision.json`

The validation corpus also includes the copied portfolio-program and prior
Mercury evidence chain under
`second-portfolio-program/portfolio-reuse-evidence/`.

---

## Decision Standard

Proceed only if all of the following are true:

- one program motion only: `second_portfolio_program`
- one review surface only: `portfolio_reuse_bundle`
- one Mercury-owned approval and revenue-boundary-guardrails path only
- no implication of generic portfolio management, account management, customer
  success, revenue operations, forecasting, billing, channel tooling, or Chio
  commercial behavior

Anything broader requires a new milestone.
