---
id: "UR-CLOSEOUT.2"
title: "Close the REL salvage PRs (#1046, #1056, #1155, #1073, #1164) after salvage"
severity: "P2"
wave: 2
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: ["REL-SALVAGE-1164.1", "REL-SALVAGE-1164.2", "REL-1.SALVAGE-1046", "REL-1.SALVAGE-1056", "REL-1.SALVAGE-1155", "REL-1.SALVAGE-1073"]
paths: ["docs/operations/PR-CARRY-FORWARD.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 2.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: section 7. Close each salvaged PR with a comment linking the salvage commit and its PR-CARRY-FORWARD rows (2 on #1046, 1 on #1073, 12 on #1164). #1164's workbench crate is not salvaged; say so.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Five PRs closed with linking comments; `python3 scripts/carry-forward-requirements.py --check --pr 1046 1073 1164` reports zero unmapped rows.

## Log
- 2026-10-09T04:51:58Z connor: created
