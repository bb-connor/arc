---
id: "UR-G0-LEDGER.3"
title: "Landing-time slot assignment tool for the merge queue"
severity: "P1"
wave: 1
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["UR-G0-LEDGER.2"]
paths: ["scripts/assign-schema-slots.py", "scripts/tests/assign-schema-slots.test.py"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.2 ("assigned in landing order, at merge time, under a lock"; "one merge queue"). In the merge queue: take the lock, move the branch's pending names to landed numbers in landing order, rewrite the Rust table and the JSON idempotently, record holder, base and merge commit, release. Refuse if the base is not the `origin/main` tip or another PR holds the lock. Wiring this into the actual merge queue configuration is an owner change; document the invocation.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `python3 scripts/tests/assign-schema-slots.test.py`: two branches landing in either order get dense numbers; re-run is idempotent; both refusal paths covered.

## Log
- 2026-10-09T04:51:58Z connor: created
