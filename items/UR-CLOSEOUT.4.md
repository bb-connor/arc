---
id: "UR-CLOSEOUT.4"
title: "Close #1173 and #1179 when their slices land"
severity: "P2"
wave: 3
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-SLICE-A.4", "WORK-SLICE-A.5", "WORK-SLICE-B.6", "WORK-SLICE-G.3", "WORK-SLICE-G.4", "WORK-SLICE-D.2", "WORK-SLICE-D.3", "WORK-SLICE-E.1", "WORK-SLICE-Z.1", "WORK-SLICE-DL.2", "REC-P6b", "REC-DOCS", "REC-EXIT", "REC-P3.N24"]
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

Roadmap: section 7 (#1173: close when the slices land; #1179 stays a draft until re-scoped and rebased). Comment on each PR with the slice-to-commit map from `SLICES.json` and `REBASE-MANIFEST.json`, confirm archive tags exist, and close. Ledger rows for #1159 (15) and #1158 (1), contained in #1173, are dispositioned here.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Both PRs closed with linking comments; `python3 scripts/carry-forward-requirements.py --check --pr 1159 1158` reports zero unmapped rows.

## Log
- 2026-10-09T04:51:58Z connor: created
