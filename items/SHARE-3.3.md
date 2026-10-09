---
id: "SHARE-3.3"
title: "Serving-path swarm admission beyond depth 1 with the tool_calls dimension"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["SHARE-1.6", "SHARE-3.1"]
paths: ["crates/kernel/chio-swarm-authority/src/verifier/**", "crates/kernel/chio-swarm-authority/src/types.rs", "crates/products/chio-cli/tests/process_host/swarm_depth.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: SHARE-3 ("serving-path swarm admission beyond depth 1 and the `tool_calls` dimension"), G3 ("swarm admission runs on the serving path"). `crates/kernel/chio-swarm-authority/src/verifier/graph.rs` checks `node.depth > graph.max_depth`; `crates/kernel/chio-process/src/store.rs:323` bounds process depth. Make swarm admission run on the process host's serving path at depth greater than 1 and add a `tool_calls` budget dimension that is held, not counted after the fact.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `crates/products/chio-cli/tests/process_host/swarm_depth.rs`: depth-3 swarm admitted within limits, depth over limit denied, `tool_calls` exhaustion denies the next call across members.
- `cargo test -p chio-swarm-authority` and the new process-host test pass.

## Log
- 2026-10-09T04:51:58Z connor: created
