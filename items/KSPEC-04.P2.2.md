---
id: "KSPEC-04.P2.2"
title: "Hosted and in-process Session closure over AP8"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["KSPEC-04.P1.4"]
paths: ["crates/protocol/chio-mcp-remote/src/remote_mcp/admin/revocation_batch.rs", "crates/kernel/chio-kernel/src/session.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-3 (KSPEC-04 phases 1 and 2: subtree closure with the dispatch-commit fence, then ProcessTree closure). Spec: `docs/superpowers/specs/2026-10-04-authority-space-teardown-design.md` (KSPEC-04). AP8 partial progress keeps the record in `Fencing`; a closure committed before release withholds the output. The workflow trigger waits for REC landing and the work trigger for WORK-W1 (add them in a follow-up once those exist).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- AP8 partial-progress and closure-before-release tests pass in `cargo test -p chio-mcp-remote closure` and `cargo test -p chio-kernel session_closure`.

## Log
- 2026-10-09T04:51:58Z connor: created
