---
id: "SHARE-2.3"
title: "Required-agent profile binds sessions to one counter (no fresh counter per session)"
severity: "P2"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["SHARE-1.2"]
paths: ["integrations/required-agents/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: SHARE-2 ("fix the required-agent profile, which issues a fresh counter per session; Megastart's bound-session pattern is the reference"). The required-agent tooling lives in `integrations/required-agents/` (`prepare-session.py`, `filesystem-policy.yaml`, `qualification/`). Change session preparation so every session of one harness under one root grant attaches to the same family hold instead of minting a new budget. Megastart (external repo `backbay-labs/chio`, PRs #9, #10, #25) already models the allowance as a kernel-held aggregate-family quota; reuse its binding shape, do not import its code.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- A new qualification test in `integrations/required-agents/qualification/` proves two sequential sessions draw down one shared quota and the second is denied when the first exhausted it.
- `python3 -m pytest integrations/required-agents/qualification -k bound_session` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
