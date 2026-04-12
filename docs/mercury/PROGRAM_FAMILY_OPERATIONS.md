# MERCURY Program Family Operations

**Date:** 2026-04-04  
**Milestone:** `v2.64`

---

## Operating Posture

`v2.64` is a bounded Mercury program-family lane over the validated
third-program chain only.

Operators must preserve three constraints:

- one motion only: `program_family`
- one review surface only: `shared_review_package`
- one Mercury-owned shared-review and portfolio-claim-discipline path only

## Export Command

```bash
cargo run -p arc-mercury -- program-family export --output target/mercury-program-family-export
```

Expected top-level artifacts:

- `program-family-profile.json`
- `program-family-package.json`
- `program-family-boundary-freeze.json`
- `program-family-manifest.json`
- `shared-review-summary.json`
- `shared-review-approval.json`
- `portfolio-claim-discipline.json`
- `family-handoff.json`

The export also carries reused evidence under `shared-review-evidence/`.

## Fail-Closed Rules

Stop the lane if:

- third-program approval refresh is absent or stale
- the scope expands beyond one named small program family
- portfolio-claim discipline is missing
- the request implies generic portfolio management, revenue-platform breadth, channel programs, or ARC commercial behavior
