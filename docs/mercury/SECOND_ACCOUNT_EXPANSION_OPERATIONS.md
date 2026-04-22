# MERCURY Second-Account Expansion Operations

**Date:** 2026-04-04  
**Milestone:** `v2.60`

---

## Operating Posture

`v2.60` is a bounded Mercury expansion lane over one renewed account and one
follow-on account only.

Operators must preserve three constraints:

- one motion only: `second_account_expansion`
- one review surface only: `portfolio_review_bundle`
- one Mercury-owned expansion approval and reuse-governance path only

If any of those constraints break, Mercury fails closed and the lane stops.

---

## Required Inputs

The export path depends on a fresh bounded renewal-qualification chain:

- renewal-qualification package
- renewal approval
- expansion-boundary handoff
- delivery-continuity evidence set
- proof and inquiry verification artifacts
- reviewer and qualification artifacts

Missing or stale renewal evidence blocks expansion packaging.

---

## Export Command

```bash
cargo run -p chio-mercury -- second-account-expansion export --output target/mercury-second-account-expansion-export
```

Expected top-level artifacts:

- `second-account-expansion-profile.json`
- `second-account-expansion-package.json`
- `portfolio-boundary-freeze.json`
- `second-account-expansion-manifest.json`
- `portfolio-review-summary.json`
- `expansion-approval.json`
- `reuse-governance.json`
- `second-account-handoff.json`

The export also carries the renewal and prior Mercury evidence chain under
`expansion-evidence/`.

---

## Review And Approval

Portfolio review stays inside Mercury and follows this order:

1. verify the renewal-qualification package still maps to the same workflow
2. confirm the second-account motion remains bounded to one follow-on account
3. issue `expansion-approval.json`
4. issue `reuse-governance.json`
5. issue `second-account-handoff.json`

No claim may imply broader multi-account expansion, portfolio tooling, or
revenue operations automation.

---

## Fail-Closed Rules

Stop the lane if any of the following occurs:

- renewal approval is absent or stale
- the requested scope expands beyond one follow-on account
- reuse governance is missing
- the request implies generic customer-success, CRM, account-management,
  revenue operations, or Chio commercial behavior

The correct response is defer or stop, not scope drift.
