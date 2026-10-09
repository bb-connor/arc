---
id: "UR-XWALK.1"
title: "ID-prefix lint for planning documents (section 12 crosswalk)"
severity: "P3"
wave: 2
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["scripts/check-id-prefixes.py", "scripts/tests/check-id-prefixes.test.sh"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 4.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: rule 4 and section 12 (program prefixes on every cross-document ID: SEC-, HOST-, WORK-, PAPER-, REC-, KSPEC-, KDEF-, STRAT-, ECON-, MKT-, UR-, FV-). Write a lint that flags bare cross-program IDs (`M1`, `W1.5`, `S1`, `D1`, `P5`, `F-15`) in new or changed planning docs under `docs/operations/`, `docs/superpowers/plans/` and `docs/superpowers/specs/` when they are not prefixed or explicitly scoped to one program in the same section. Diff-only mode by default so historical documents are not churned.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Test fixtures cover the four historical collisions the roadmap names (#1173 D1 vs KDEF-D1, #1173 S1 vs KSPEC-01, REC-P5 vs PAPER-5, SEC-M1 vs HOST-M1).
- `python3 scripts/check-id-prefixes.py --diff origin/main` runs clean on the lane branch.

## Log
- 2026-10-09T04:51:58Z connor: created
