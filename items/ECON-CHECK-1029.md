---
id: "ECON-CHECK-1029"
title: "Check #1029's three economy items against main and close it"
severity: "P2"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["UR-LEDGER-CARRY", "ECON-SALVAGE-956"]
paths: ["docs/operations/PR-CARRY-FORWARD.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 4.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: section 7 (#1029: close as superseded by #1160 after checking its three economy items against main: settlement-observer idempotency key, credit election, MustPrepay; its ADR-0018 collides with main's ADR-0018 and must be renumbered if any of it survives). Source: PR #1029 (ref `origin/codex/chio-security-execution`). For each item, find the PR's implementation and main's equivalent; record present-on-main, missing (open a follow-up backlog note), or obsolete. #1029's singular-approval ADR decision is an owner decision (parked UR-PK-1029-ADR); record it, do not decide it.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- PR-CARRY-FORWARD has a #1029 section with the three items, evidence paths on main, and the ADR-0018 renumbering note.
- #1029 closed with a comment linking that section (after the owner decision is recorded or explicitly deferred).

## Log
- 2026-10-09T04:51:58Z connor: created
