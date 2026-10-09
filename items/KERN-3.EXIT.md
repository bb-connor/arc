---
id: "KERN-3.EXIT"
title: "Implement process exit as an authority transition"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["KERN-3.EXIT-SPEC", "KSPEC-04.P2.1", "UR-G0-LEDGER.4"]
paths: ["crates/kernel/chio-process/src/types.rs", "crates/kernel/chio-process/src/store.sql", "crates/kernel/chio-process/src/worker.rs", "crates/products/chio-cli/src/cli/process_host/runner/journal.rs", "crates/products/chio-cli/src/cli/process_host/runner/supervision.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-3. Implement KERN-3.EXIT-SPEC. `store.rs` and `lib.rs` changes follow KSPEC-04.P2.1 (same files; minimal edits listed in the PR).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Host-side `ProcessRuntime` invocation of an exited process is refused; children of an exited parent follow the orphan policy; `cargo test -p chio-process exit` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
