---
id: "SHARE-1.5"
title: "Process shares and the finding pool as views over the hold ledger"
severity: "P2"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["SHARE-1.2"]
paths: ["crates/kernel/chio-process/src/store.rs", "crates/kernel/chio-process/src/types.rs", "crates/kernel/chio-process/tests/shares_view.rs", "crates/kernel/chio-kernel/src/finding_pool.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: SHARE-1 ("every other counter becomes a commitment entry or a view"). Re-express `chio-process` process-tree limits that represent consumption (calls, spend) as views over the kernel hold ledger rather than independent counters, leaving structural limits (`max_processes`, `max_depth`) as structural. Do the same for the finding pool behind the default-off `finding-market` feature. The hold ledger stays the only durable consumption authority.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `crates/kernel/chio-process/tests/shares_view.rs` proves a process-level consumption read equals the hold-ledger value after holds, captures, releases and a restart.
- `cargo test -p chio-process` and `cargo test -p chio-kernel --features finding-market finding_pool` pass.

## Log
- 2026-10-09T04:51:58Z connor: created
