# MERCURY Portfolio Revenue Boundary Operations

**Date:** 2026-04-04  
**Milestone:** `v2.65`

---

## Operating Posture

`v2.65` is a bounded Mercury portfolio-revenue-boundary lane over the
validated program-family chain only.

Operators must preserve three constraints:

- one motion only: `portfolio_revenue_boundary`
- one review surface only: `commercial_review_bundle`
- one Mercury-owned commercial-review and channel-boundary path only

## Export Command

```bash
cargo run -p chio-mercury -- portfolio-revenue-boundary export --output target/mercury-portfolio-revenue-boundary-export
```

Expected top-level artifacts:

- `portfolio-revenue-boundary-profile.json`
- `portfolio-revenue-boundary-package.json`
- `revenue-boundary-freeze.json`
- `revenue-boundary-manifest.json`
- `commercial-review-summary.json`
- `commercial-approval.json`
- `channel-boundary-rules.json`
- `commercial-handoff.json`

The export also carries reused evidence under `commercial-review-evidence/`.

## Fail-Closed Rules

Stop the lane if:

- program-family shared-review approval is absent or stale
- the scope expands beyond one named commercial handoff
- channel-boundary rules are missing
- the request implies generic revenue-platform, billing, channel, or Chio commercial behavior
