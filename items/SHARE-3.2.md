---
id: "SHARE-3.2"
title: "Live cancel and revoke while the host runs, cascading through the tree"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["SHARE-3.1", "KSPEC-04.P2.1"]
paths: ["crates/products/chio-cli/src/cli/process_host/lifecycle.rs", "crates/products/chio-cli/tests/process_host/live_revoke.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: SHARE-3 ("live cancel and revoke while the host runs"), G3 ("live cancel and revoke cascade through the tree"). Build on KSPEC-04 subtree and ProcessTree closure (KERN-3). Revoking a grant mid-run must deny every new call in the subtree before effect and cancel in-flight work through the dispatch-commit fence; the process host surfaces the revocation to each harness session.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `crates/products/chio-cli/tests/process_host/live_revoke.rs`: revoke root mid-run denies all children within one dispatch; cancel of a subtree leaves siblings running; every denial has a signed receipt.
- `cargo test -p chio-cli --features real-linux-enforcement live_revoke` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
