---
id: "UR-G0-COLLIDE.1"
title: "Trigger-name collision lint (fixes the fail-open duplicate delete guard)"
severity: "P1"
wave: 1
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["crates/platform/chio-store-sqlite/tests/schema_object_names.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.2 ("Duplicate trigger, fails open: `admission_operation_recovery_no_delete` is defined by #1160 on its deferrals table and by #1179 on its records table, both with `CREATE TRIGGER IF NOT EXISTS`. After a merge, the second delete guard is silently skipped"). Sites: #1160 `crates/platform/chio-store-sqlite/src/admission_operation_store/recovery/schema.sql:20`; #1179 `crates/platform/chio-store-sqlite/src/admission_operation_recovery.sql:26`. Catalog verification (`verify_admission_operation_schema`, `schema.rs:602`) compares on-disk DDL text with an in-memory DB built from the same batches, so both sides miss the guard and verification passes. It is the only cross-PR trigger name collision (all 512-549 triggers scanned). Do not ban `IF NOT EXISTS` (448 sites; DDL text is compared, so removal needs migrations). Instead scan `chio-store-sqlite/src/**/*.{sql,rs}`, `crates/kernel/chio-process/src/store.sql` and `src/mailboxes/store.sql` for `CREATE TRIGGER`, fail when one name binds two tables, and after a fresh admission-store open assert every declared trigger whose table exists is present with that `tbl_name`. Passes on #1160 today; blocks the #1179 rebase until the trigger is renamed (REC-P0P1.9 renames it).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-store-sqlite --test schema_object_names` (`trigger_names_bind_one_table`, `declared_guard_triggers_exist_on_declared_table`, `duplicate_trigger_fixture_is_rejected`) passes.

## Log
- 2026-10-09T04:51:58Z connor: created
