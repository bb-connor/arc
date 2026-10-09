---
id: "SHARE-1.6"
title: "D1 delegation slots and S1 swarm pools as hold-ledger commitment entries"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["SHARE-1.2", "WORK-SLICE-B.2", "WORK-SLICE-B.4"]
paths: ["crates/kernel/chio-swarm-authority/src/**", "crates/kernel/chio-swarm-authority/tests/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: SHARE-1 (D1 slots and S1 pools are two of the seven counters). After #1173 slice beta lands D1 dynamic delegation and S1 swarm evolution on main, re-express their slots and pools as `Commitment` entries (KSPEC-03 typed ledger vocabulary) against the family hold so a delegated child's spend and invocations are pooled across children (today money is not pooled across delegated children and the only shared sibling pool counts invocations across one hop). If slice beta placed the code outside `chio-swarm-authority`, narrow `paths` to the actual files at claim time and record the change in the PR.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Tests prove: money is pooled across delegated children under one family cap; S1 pool exhaustion denies new swarm members; restart does not replenish slots or pools.
- `cargo test -p chio-swarm-authority` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
