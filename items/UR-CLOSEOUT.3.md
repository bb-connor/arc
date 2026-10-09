---
id: "UR-CLOSEOUT.3"
title: "Close the economy PRs #956 to #959 after salvage"
severity: "P2"
wave: 3
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: ["ECON-SALVAGE-956", "ECON-SALVAGE-958", "ECON-SALVAGE-959", "SHARE-1.2", "ECON-CHECK-1029"]
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

Roadmap: section 7. Close #956, #957, #958 and #959 once every ledger row is dispositioned in PR-CARRY-FORWARD (136 rows on #957 to #959, 27 on #956). #957's Chio Pass kernel gating and #959's closed-enum wire break are dropped by design; say so in the closing comments.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- The four PRs are closed with comments linking their PR-CARRY-FORWARD rows; `python3 scripts/carry-forward-requirements.py --check --pr 956 957 958 959` reports zero unmapped rows.

## Log
- 2026-10-09T04:51:58Z connor: created
