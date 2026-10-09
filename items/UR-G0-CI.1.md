---
id: "UR-G0-CI.1"
title: "Wire the Gate 0 gates into CI"
severity: "P1"
wave: 1
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: ["UR-G0-LEDGER.3", "CT-ABI.1", "CT-WIRE.1", "UR-G0-COLLIDE.1"]
paths: [".github/workflows/ci.yml"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 2.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: Gate 0 exit ("the ledger lock is live"). Neither `scripts/check-security-landing-ledger.py` nor its test runs in CI today. Add `run_gate` lines (structural gates block, around `ci.yml` lines 130-225, same pattern as `scripts/check-trust-boundaries.py`) for: the schema-slot ledger checker and test, the kernel ABI census checker and test, the preview-freeze checker and test, and the landing-ledger checker and test. One item owns `ci.yml` edits for Gate 0 so contract items need no lease on it. Making these required checks is an owner branch-protection change; list it in the PR.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `python3 scripts/check-security-ci-contract.py` and its test pass; a hosted run shows each new gate executing and passing.

## Log
- 2026-10-09T04:51:58Z connor: created
