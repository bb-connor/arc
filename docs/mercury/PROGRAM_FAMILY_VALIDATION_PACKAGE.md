# MERCURY Program Family Validation Package

**Date:** 2026-04-04  
**Milestone:** `v2.64`

---

## Purpose

This package validates that Mercury can qualify one bounded program-family
lane without widening into generic portfolio-management or revenue-platform
behavior.

The supported claim is narrow:

> Mercury can qualify one bounded program family through one `program_family`
> motion using one `shared_review_package` rooted in the validated
> third-program chain.

## Generation Command

```bash
cargo run -p chio-mercury -- program-family validate --output target/mercury-program-family-validation
```

## Expected Layout

- `program-family/program-family-package.json`
- `program-family/program-family-boundary-freeze.json`
- `program-family/shared-review-summary.json`
- `program-family/shared-review-approval.json`
- `program-family/portfolio-claim-discipline.json`
- `program-family/family-handoff.json`
- `validation-report.json`
- `program-family-decision.json`
