---
id: "WORK-W3.3c"
title: "W3: two reference applications and lifecycle cases LC01-LC06"
severity: "P2"
wave: 4
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-W2.4", "WORK-W3.2b", "WORK-W3.2c", "WORK-W3.3b", "WORK-W2.5a"]
paths: ["examples/owner-work/api_review.py", "examples/owner-work/support_disclosure.mjs", "examples/owner-work/scenarios.json", "examples/owner-work/api_review_langgraph.py"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 16.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Plans and specs (landed by WORK-SLICE-C.1): `docs/superpowers/plans/2026-10-03-work-runtime.md`, `2026-10-03-work-owner-services.md`, `2026-10-03-work-developer-surface.md`; specs `docs/superpowers/specs/2026-10-03-work-runtime-design.md`, `work-owner-services-design.md`, `work-developer-surface-design.md`, `agentic-work-kernel-design.md`; real constructor inventory in `docs/research/work-abstraction/INTEGRATION.md` (WORK-W1.0). Two applications an outside team can run as their agent proposing work (success-test criterion (b)).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- LC01 to LC06 pass end to end on two hosts; results recorded.

## Log
- 2026-10-09T04:51:58Z connor: created
