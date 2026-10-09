---
id: "UR-G0-COLLIDE.2"
title: "Projection-kind registry for the authority_global_commits CHECK list"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["UR-G0-LEDGER.1"]
paths: ["crates/platform/chio-store-sqlite/src/serving_owner/global_commit_chain/projection_kinds.rs", "crates/platform/chio-store-sqlite/src/serving_owner/global_commit_chain/schema_migration.rs", "crates/platform/chio-store-sqlite/src/serving_owner/global_commit_chain/schema_tests.rs", "crates/platform/chio-store-sqlite/src/serving_owner/global_commit_chain.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.2 ("Global-commit kind list: the `authority_global_commits` projection-kind CHECK list is appended separately in #1160, #1173 and #1179"). The CHECK is in `crates/platform/chio-store-sqlite/src/serving_owner/global_commit_chain.rs:46-47`; each PR also prepends its kind to the reverse strip list in `global_commit_chain/schema_migration.rs`, which matches legacy catalogs by stripping kinds from the end, so final order must equal landing order. #1160 adds `security_participant_checkpoint`, #1173 `payment_resolution`, #1179 `recovery`. Create one ordered `PROJECTION_KINDS` registry; the migration iterates its non-base suffix in reverse; the DDL stays byte-identical. Later rebases append one line each, in ledger-lock order.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-store-sqlite global_commit_chain::schema_tests` and `projection_kinds::` (`check_list_matches_registry_order`, `migration_strip_order_is_registry_suffix_reversed`, `every_kind_has_projection_reference`) pass.

## Log
- 2026-10-09T04:51:58Z connor: created
