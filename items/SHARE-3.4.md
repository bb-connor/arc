---
id: "SHARE-3.4"
title: "Restart never replenishes a pool: crash and restart suite"
severity: "P2"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["SHARE-1.3", "SHARE-3.1", "SHARE-2.1"]
paths: ["crates/products/chio-cli/tests/process_host/restart_no_replenish.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: SHARE-3 and G3 ("restart never replenishes a pool"). A single suite that kills the kernel and process host at each lifecycle point (after hold, after dispatch, after capture, after reconcile) and asserts no pool (family cap, sibling registry, model spend, token quota, swarm pool) is larger after restart than before.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- The suite runs at least four kill points times five pool kinds and passes: `cargo test -p chio-cli --features real-linux-enforcement restart_no_replenish`.

## Log
- 2026-10-09T04:51:58Z connor: created
