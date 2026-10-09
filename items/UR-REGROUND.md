---
id: "UR-REGROUND"
title: "Refresh the unified roadmap after #1160: section 2 state and every pin"
severity: "P1"
wave: 1
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["docs/operations/UNIFIED_ROADMAP.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 3.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: section 13 ("This document: refresh section 2 and every pin"; "every line citation in this file must be re-verified after #1160 merges"). If PR #1196 has merged, edit `docs/operations/UNIFIED_ROADMAP.md`; otherwise import it from `origin/docs/unified-roadmap-20261008` first. Update the pin table (main becomes the #1160 merge commit; #1179 head is now 44c714d96, not the pinned 491bd01b5), section 2's #1160 row (merged), and re-verify every file:line citation (for example README lines in section 9 shift after the merge; `crates/kernel/chio-kernel/src/payment.rs` `default_true` is at line 958 and the field at 496-497). Keep the document's rules: no internal dates, no capacity projections.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Every `path:line` or `path` citation in the roadmap resolves on post-#1160 main (a script or command transcript in the commit body proves it).
- The pin table and section 2 reflect post-merge state; no em dashes.

## Log
- 2026-10-09T04:51:58Z connor: created
