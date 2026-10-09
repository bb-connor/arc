---
id: "KSPEC-08.P1.3"
title: "Per-scope stop-intent journal in the lock root (S25)"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["KSPEC-08.P1.2"]
paths: ["crates/platform/chio-store-sqlite/src/serving_owner/stop_intent.rs", "crates/platform/chio-store-sqlite/src/serving_owner.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-1 (KSPEC-08 phase 1: KDEF-D2, N22, N23; durable restart-safe stop with an allocated schema slot; reachable from the process-host socket and the CLI). Spec: `docs/superpowers/specs/2026-10-04-durable-stop-epoch-design.md` (rule numbers S1 to S38 below refer to it). 
An fsynced journal beside `rollback_anchor.rs`, keyed by scope, satisfied and removed only after the anchor is written. A full journal reports `process_only` and never evicts an entry. Register the journal format identifier through the ledger lock.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Crash-injection tests: journal write then kill before commit yields `ready_stopped`/`latch_only`; two pending scopes; `SQLITE_FULL`; a database-only restore keeps the intent. `cargo test -p chio-store-sqlite stop_intent` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
