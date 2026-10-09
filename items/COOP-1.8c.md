---
id: "COOP-1.8c"
title: "`chio key init|show` over OS key refs"
severity: "P1"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["COOP-1.8a"]
paths: ["crates/products/chio-cli/src/cli/types/key.rs", "crates/products/chio-cli/src/cli/dispatch/key.rs", "crates/products/chio-cli/tests/key_custody.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 4.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-1 ("HOST-M1, re-cut server-first"), G2 steps (passport, challenge, inbox, holder pickup, allow and deny at the door, offline verification against a pinned partner card). Plan source: #1177 `docs/superpowers/plans/2026-10-08-m1-cooperate-0.md` as re-cut by COOP-1.0. HOST-M1 never depends on #1179. One variant line in `cli/types.rs` `Commands` (shared serialization point with other CLI items).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-cli --test key_custody` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
