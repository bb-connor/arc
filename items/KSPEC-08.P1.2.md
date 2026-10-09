---
id: "KSPEC-08.P1.2"
title: "Durable stop chain in the admission serving writer (schema slot)"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-CTRL.3", "UR-G0-LEDGER.2", "UR-G0-LEDGER.4", "UR-G0-COLLIDE.2"]
paths: ["crates/platform/chio-store-sqlite/src/admission_operation_store/stop_epoch.rs", "crates/platform/chio-store-sqlite/src/admission_operation_store/stop_epoch/**", "crates/platform/chio-store-sqlite/src/admission_operation_store/schema/migration_stop_epoch.rs", "crates/platform/chio-store-sqlite/src/admission_operation_store.rs", "crates/platform/chio-store-sqlite/src/admission_operation_store/schema.rs", "crates/platform/chio-store-sqlite/src/serving_owner/global_commit_chain.rs", "crates/platform/chio-store-sqlite/src/serving_owner/global_commit_chain/schema_migration.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 16.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-1 (KSPEC-08 phase 1: KDEF-D2, N22, N23; durable restart-safe stop with an allocated schema slot; reachable from the process-host socket and the CLI). Spec: `docs/superpowers/specs/2026-10-04-durable-stop-epoch-design.md` (rule numbers S1 to S38 below refer to it). 
Create tables `admission_operation_stop_epochs`, `_stop_notes` and `_stop_signing` (S38). Commit restrictively under S1 and S2 with resume headroom (S6), rollover, and the signing obligation (resume refuses with `StopEvidencePending`). Add the `stop_epoch` projection kind to the `authority_global_commits` CHECK list (`serving_owner/global_commit_chain.rs:47`, a collision point: go through the ledger lock and its CHECK-list registry). Distinguish "absent before migration" from "missing after migration" (S34). Take the schema slot by symbolic name from the ledger lock.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-store-sqlite stop_epoch` covers S2 gap, mismatch, idempotent and Restrict-narrowing cases, headroom at `bound - 1`, rollover representability, and an unsigned rollover blocking resume.
- The slot appears in the ledger lock file and the CHECK-list registry check passes.

## Log
- 2026-10-09T04:51:58Z connor: created
