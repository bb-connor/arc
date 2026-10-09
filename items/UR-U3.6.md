---
id: "UR-U3.6"
title: "Turn on the retired-phrase gate in CI for public copy"
severity: "P1"
wave: 2
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: ["UR-U3.1", "UR-U3.2", "UR-U3.3", "UR-U3.4", "UR-U3.5"]
paths: [".github/workflows/docs-positioning.yml"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 2.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: OUT-2 (positioning cleanup stays clean). Add a small workflow that runs `python3 scripts/check-native-host-docs.py --rule retired-phrases --rule em-dash` on pull requests touching `README.md`, `AGENTS.md`, `docs/**`, `spec/PROTOCOL.md` or `docs/assets/**`. Keep it a separate non-required job until the owner adds it to branch protection (hosted CI is a serialization point; do not change required checks yourself).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- The workflow passes on the lane branch and fails on a scratch commit that reintroduces "Agents that pay each other" into README.md (show both runs or an `act` log).

## Log
- 2026-10-09T04:51:58Z connor: created
