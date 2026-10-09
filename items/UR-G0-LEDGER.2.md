---
id: "UR-G0-LEDGER.2"
title: "Symbolic schema-slot resolver in chio-store-sqlite"
severity: "P1"
wave: 1
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["UR-G0-LEDGER.1"]
paths: ["crates/platform/chio-store-sqlite/src/schema_slots.rs", "crates/platform/chio-store-sqlite/src/lib.rs", "crates/platform/chio-store-sqlite/src/admission_operation_store.rs", "crates/platform/chio-store-sqlite/src/tool_outcome_store.rs", "crates/platform/chio-store-sqlite/tests/schema_slot_ledger.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.2 (symbolic version names on branches). Add const tables per store: landed `(name, slot)` plus a branch-local `PENDING: &[&str]`; `const fn slot(name)` resolves a pending name to `landed_max + 1 + index`, so a rebase shifts numbers with no code edits. SUPPORTED constants become `max_slot()` (edit only line 230 of `admission_operation_store.rs` and line 28 of `tool_outcome_store.rs`). History up to v36 keeps its literals. No behaviour change.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-store-sqlite --test schema_slot_ledger` (`rust_slot_table_matches_ledger_json`) and `cargo test -p chio-store-sqlite schema_slots::` (`landed_slots_resolve_to_history`, `pending_slot_resolves_after_landed_max`, `supported_version_is_max_slot`) pass; existing `admission_operation_store_tests::schema` stays green.

## Log
- 2026-10-09T04:51:58Z connor: created
