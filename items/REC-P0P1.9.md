---
id: "REC-P0P1.9"
title: "Store schema slots and core recovery records (trigger rename, dead v41 check)"
severity: "P2"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["UR-G0-LEDGER.4", "UR-G0-COLLIDE.1", "UR-G0-COLLIDE.2", "REC-P0P1.5"]
paths: ["crates/platform/chio-store-sqlite/src/admission_operation_recovery.sql", "crates/platform/chio-store-sqlite/src/admission_operation_store/recovery.rs", "crates/platform/chio-store-sqlite/src/admission_operation_store/retained_request.rs", "crates/platform/chio-store-sqlite/src/admission_operation_store/recovery/*.rs", "crates/platform/chio-store-sqlite/src/admission_operation_store/schema.rs", "crates/platform/chio-store-sqlite/src/admission_operation_store/schema/migration_recovery_*.rs", "crates/platform/chio-store-sqlite/src/admission_operation_store.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 16.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method (applies to every REC-P0P1 slice): do not run `git rebase`. Re-land from the frozen #1179 source `f217de1fb` (PR head; the roadmap pin 491bd01b5 is stale) onto `integration/beta-next` by path: `git checkout f217de1fb -- <slice globs>`, then repair against #1160's code, and record the slice's source-manifest digest in `docs/architecture/recoverable-agent-runtime/implementation/REBASE-MANIFEST.json` (created by REC-P0P1.0). Keep each slice compiling: new kernel trait methods land with fail-closed default bodies (#1160 precedent `store.rs:874`); `recovery_authority()` returns `None` until the store slices land. Never hand-merge `_generated` files (REC-P0P1.17 regenerates). Roadmap Lane REC requirements this lane must meet: rebase onto #1160's paged sweep rather than porting the old loop; adopt CT-SETTLE and the KSPEC-08 stop chain (KDEF-N24); adopt process ABI v4 (KDEF-N13) and the cage port (KDEF-N16); fix KDEF-N15 (wall-clock time in authority evidence); fix every open P1; take schema slots through the ledger lock; regenerate the SDKs. The #1179 rebase is one of the two riskiest pieces in the roadmap and gets the earliest prototype. Collision rider (G0.2): take symbolic slots from the ledger lock (#1179 used admission v35 to v40 and hard-coded 41; #1160 already used v35/v36 for other tables); rename #1179's trigger to `admission_operation_recovery_records_no_delete` so it no longer collides with #1160's deferrals guard; rename #1179's colliding `admission_operation_store/recovery` module; remove or make symbolic the dead v41 check (`recovery/original_owner.rs:385` `!= 41`, and `:405-416`); append the `recovery` projection kind through the registry. Propose collapsing #1179's never-released intermediate formats (v37 to v39 and the v40 encoding step) into the minimum number of slots; collapsing breaks ignored legacy-capture tests (`authority_history.rs:2705,2867`), so record the proposal for the owner with D3.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-store-sqlite --lib admission_operation_store::recovery` passes including new `both_recovery_delete_guards_installed`; `cargo test -p chio-store-sqlite --test schema_object_names` and the schema-slot checker pass; schema tests under `admission_operation_store_tests/schema*` pass.

## Log
- 2026-10-09T04:51:58Z connor: created
