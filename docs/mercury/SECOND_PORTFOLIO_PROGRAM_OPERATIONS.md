# MERCURY Second Portfolio Program Operations

**Date:** 2026-04-04  
**Milestone:** `v2.62`

---

## Operating Posture

`v2.62` is a bounded Mercury second-portfolio-program lane over the validated
portfolio-program chain only.

Operators must preserve three constraints:

- one motion only: `second_portfolio_program`
- one review surface only: `portfolio_reuse_bundle`
- one Mercury-owned portfolio-reuse approval and revenue-boundary-guardrails
  path only

If any of those constraints break, Mercury fails closed and the lane stops.

---

## Required Inputs

The export path depends on a fresh bounded portfolio-program chain:

- portfolio-program package
- portfolio approval
- revenue-operations guardrails
- program handoff
- second-account-expansion, renewal-qualification, and delivery-continuity
  evidence
- proof and inquiry verification artifacts
- reviewer and qualification artifacts

Missing or stale portfolio-program evidence blocks second-portfolio-program
packaging.

---

## Export Command

```bash
cargo run -p chio-mercury -- second-portfolio-program export --output target/mercury-second-portfolio-program-export
```

Expected top-level artifacts:

- `second-portfolio-program-profile.json`
- `second-portfolio-program-package.json`
- `second-portfolio-program-boundary-freeze.json`
- `second-portfolio-program-manifest.json`
- `portfolio-reuse-summary.json`
- `portfolio-reuse-approval.json`
- `revenue-boundary-guardrails.json`
- `second-program-handoff.json`

The export also carries the portfolio-program and prior Mercury evidence chain
under `portfolio-reuse-evidence/`.

---

## Review And Approval

Portfolio reuse review stays inside Mercury and follows this order:

1. verify the portfolio-program package still maps to the same workflow
2. confirm the second-portfolio-program scope remains bounded to one adjacent
   program only
3. issue `portfolio-reuse-approval.json`
4. issue `revenue-boundary-guardrails.json`
5. issue `second-program-handoff.json`

No claim may imply generic portfolio management, account management,
customer-success automation, revenue operations, forecasting, billing, channel
programs, or Chio commercial behavior.

---

## Fail-Closed Rules

Stop the lane if any of the following occurs:

- portfolio-program approval is absent or stale
- the requested scope expands beyond one bounded adjacent second portfolio
  program
- revenue-boundary guardrails are missing
- the request implies generic portfolio management, account management,
  customer success, revenue operations, forecasting, billing, channel, or Chio
  commercial behavior

The correct response is defer or stop, not scope drift.
