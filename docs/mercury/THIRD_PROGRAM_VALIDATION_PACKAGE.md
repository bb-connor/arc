# MERCURY Third Program Validation Package

**Date:** 2026-04-04  
**Milestone:** `v2.63`

---

## Purpose

This package validates that Mercury can qualify one bounded third-program lane
without widening into generic multi-program portfolio-management or revenue
platform behavior.

The supported claim is narrow:

> Mercury can qualify one bounded third program through one `third_program`
> motion using one `multi_program_reuse_bundle` rooted in the validated
> second-portfolio-program chain.

## Generation Command

```bash
cargo run -p chio-mercury -- third-program validate --output target/mercury-third-program-validation
```

## Expected Layout

- `third-program/third-program-package.json`
- `third-program/third-program-boundary-freeze.json`
- `third-program/multi-program-reuse-summary.json`
- `third-program/approval-refresh.json`
- `third-program/multi-program-guardrails.json`
- `third-program/third-program-handoff.json`
- `validation-report.json`
- `third-program-decision.json`

Anything broader requires a new milestone.
