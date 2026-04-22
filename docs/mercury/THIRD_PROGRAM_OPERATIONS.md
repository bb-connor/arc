# MERCURY Third Program Operations

**Date:** 2026-04-04  
**Milestone:** `v2.63`

---

## Operating Posture

`v2.63` is a bounded Mercury third-program lane over the validated
second-portfolio-program chain only.

Operators must preserve three constraints:

- one motion only: `third_program`
- one review surface only: `multi_program_reuse_bundle`
- one Mercury-owned approval-refresh and multi-program-guardrails path only

If any of those constraints break, Mercury fails closed and the lane stops.

## Required Inputs

The export path depends on a fresh bounded second-portfolio-program chain:

- second-portfolio-program package
- portfolio-reuse approval
- revenue-boundary guardrails
- second-program handoff
- portfolio-program evidence
- proof and inquiry verification artifacts
- reviewer and qualification artifacts

## Export Command

```bash
cargo run -p chio-mercury -- third-program export --output target/mercury-third-program-export
```

Expected top-level artifacts:

- `third-program-profile.json`
- `third-program-package.json`
- `third-program-boundary-freeze.json`
- `third-program-manifest.json`
- `multi-program-reuse-summary.json`
- `approval-refresh.json`
- `multi-program-guardrails.json`
- `third-program-handoff.json`

The export also carries the reused evidence chain under `multi-program-evidence/`.

## Fail-Closed Rules

Stop the lane if:

- second-portfolio-program approval is absent or stale
- the requested scope expands beyond one bounded repeated adjacent-program reuse decision
- multi-program guardrails are missing
- the request implies generic portfolio management, revenue operations, billing, channel, or Chio commercial behavior
