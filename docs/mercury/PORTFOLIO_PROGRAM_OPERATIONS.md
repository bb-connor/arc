# MERCURY Portfolio Program Operations

**Date:** 2026-04-04  
**Milestone:** `v2.61`

---

## Operating Posture

`v2.61` is a bounded Mercury portfolio-program lane over the validated
second-account-expansion chain only.

Operators must preserve three constraints:

- one motion only: `portfolio_program`
- one review surface only: `program_review_bundle`
- one Mercury-owned portfolio approval and revenue-operations-guardrails path
  only

If any of those constraints break, Mercury fails closed and the lane stops.

---

## Required Inputs

The export path depends on a fresh bounded second-account-expansion chain:

- second-account-expansion package
- expansion approval
- reuse governance
- second-account handoff
- renewal-qualification and delivery-continuity evidence
- proof and inquiry verification artifacts
- reviewer and qualification artifacts

Missing or stale second-account-expansion evidence blocks portfolio-program
packaging.

---

## Export Command

```bash
cargo run -p arc-mercury -- portfolio-program export --output target/mercury-portfolio-program-export
```

Expected top-level artifacts:

- `portfolio-program-profile.json`
- `portfolio-program-package.json`
- `portfolio-program-boundary-freeze.json`
- `portfolio-program-manifest.json`
- `program-review-summary.json`
- `portfolio-approval.json`
- `revenue-operations-guardrails.json`
- `program-handoff.json`

The export also carries the second-account-expansion and prior Mercury
evidence chain under `portfolio-evidence/`.

---

## Review And Approval

Program review stays inside Mercury and follows this order:

1. verify the second-account-expansion package still maps to the same workflow
2. confirm the portfolio-program scope remains bounded to one reviewed program
3. issue `portfolio-approval.json`
4. issue `revenue-operations-guardrails.json`
5. issue `program-handoff.json`

No claim may imply generic account management, customer success, revenue
operations automation, forecasting, billing, or ARC commercial behavior.

---

## Fail-Closed Rules

Stop the lane if any of the following occurs:

- second-account expansion approval is absent or stale
- the requested scope expands beyond one bounded portfolio program
- revenue-operations guardrails are missing
- the request implies generic account-management, customer-success, revenue
  operations, forecasting, billing, channel, or ARC commercial behavior

The correct response is defer or stop, not scope drift.
