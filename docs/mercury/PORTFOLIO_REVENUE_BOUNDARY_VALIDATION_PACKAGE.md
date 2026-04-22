# MERCURY Portfolio Revenue Boundary Validation Package

**Date:** 2026-04-04  
**Milestone:** `v2.65`

---

## Purpose

This package validates that Mercury can qualify one bounded
portfolio-revenue-boundary lane without widening into generic revenue-platform
or channel-program behavior.

The supported claim is narrow:

> Mercury can qualify one bounded portfolio revenue boundary through one
> `portfolio_revenue_boundary` motion using one `commercial_review_bundle`
> rooted in the validated program-family chain.

## Generation Command

```bash
cargo run -p chio-mercury -- portfolio-revenue-boundary validate --output target/mercury-portfolio-revenue-boundary-validation
```

## Expected Layout

- `portfolio-revenue-boundary/portfolio-revenue-boundary-package.json`
- `portfolio-revenue-boundary/revenue-boundary-freeze.json`
- `portfolio-revenue-boundary/commercial-review-summary.json`
- `portfolio-revenue-boundary/commercial-approval.json`
- `portfolio-revenue-boundary/channel-boundary-rules.json`
- `portfolio-revenue-boundary/commercial-handoff.json`
- `validation-report.json`
- `portfolio-revenue-boundary-decision.json`
