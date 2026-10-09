---
id: "REC-DOCS"
title: "Land #1179's implementation docs and status; archive the P6 evidence tree by tag"
severity: "P3"
wave: 3
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: ["REC-1172", "REC-P0P1.Q"]
paths: ["docs/architecture/recoverable-agent-runtime/implementation/p0/**", "docs/architecture/recoverable-agent-runtime/implementation/p1/**", "docs/architecture/recoverable-agent-runtime/implementation/STATUS.md", "docs/architecture/recoverable-agent-runtime/implementation/README.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: Lane REC, section 7 (#1179 stays a draft until re-scoped and rebased). Land the per-phase plans and status from #1179 (`f217de1fb`) without the 5,102-file `p6/evidence` tree: tag it (`archive/pr1179-p6-evidence`) and keep its hashes in the docs. Update STATUS.md to the re-land state and slice IDs. Extend `paths` to `p2/` to `p6/` plan files (not evidence) at claim time.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Docs build links resolve; the archive tag exists on origin; STATUS.md maps every phase to its REC backlog item.

## Log
- 2026-10-09T04:51:58Z connor: created
