---
id: "KSPEC-04.P1.1"
title: "Authority-refs index, closure fences and closure-record tables (schema slot)"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["UR-G0-LEDGER.4", "UR-G0-COLLIDE.2", "KSPEC-08.P1.2"]
paths: ["crates/platform/chio-store-sqlite/src/admission_operation_store/authority_refs.rs", "crates/platform/chio-store-sqlite/src/admission_operation_store/closure.rs", "crates/platform/chio-store-sqlite/src/admission_operation_store/schema/migration_closure.rs", "crates/platform/chio-store-sqlite/src/admission_operation_store.rs", "crates/platform/chio-store-sqlite/src/admission_operation_store/schema.rs", "crates/platform/chio-store-sqlite/src/serving_owner/global_commit_chain.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-3 (KSPEC-04 phases 1 and 2: subtree closure with the dispatch-commit fence, then ProcessTree closure). Spec: `docs/superpowers/specs/2026-10-04-authority-space-teardown-design.md` (KSPEC-04). Backfill and the legacy predicate: a `legacy_unindexed` operation fails its dispatch CAS once any fence exists. Ordered after KSPEC-08.P1.2 because both touch `global_commit_chain.rs`; take the slot through the ledger lock.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Backfill re-derives equal refs; `legacy_unindexed` fails its CAS once a fence exists; `cargo test -p chio-store-sqlite closure` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
