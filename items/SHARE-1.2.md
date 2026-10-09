---
id: "SHARE-1.2"
title: "Family monetary cap on the kernel hold ledger using the #957 co-debit pattern"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["SHARE-1.1", "UR-G0-LEDGER.2", "UR-G0-LEDGER.4"]
paths: ["crates/kernel/chio-kernel/src/budget_store.rs", "crates/kernel/chio-kernel/src/budget_store/**", "crates/kernel/chio-kernel/src/kernel/family_cap.rs", "crates/kernel/chio-kernel/src/kernel/tests/family_cap.rs", "crates/platform/chio-store-sqlite/src/admission_operation_store/budget_custody.rs", "crates/platform/chio-store-sqlite/src/admission_operation_store_tests/family_cap.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: SHARE-1 first slice ("a family monetary cap, using #957's co-debit pattern"), G3 ("the family money cap ... held"). Salvage the co-debit pattern from PR #957 (ref `origin/chio/m0-pass-build`): `crates/kernel/chio-kernel/src/kernel/validation.rs` around lines 866-902 (aggregate pool co-debit on hold, reconcile down on lower realized cost, "must co-debit" invariant), `crates/kernel/chio-kernel/src/kernel/kernel_struct.rs` around 518-551, and tests `crates/kernel/chio-kernel/src/kernel/tests/free_tier_pool.rs`. Drop the Chio Pass kernel gating entirely (roadmap section 7). Implement a family (root grant plus delegated descendants) monetary ceiling that every child hold co-debits atomically in the same store transaction as the child's own hold; reconcile and release co-debit symmetrically. Allocate the store schema version through the ledger lock (symbolic slot name until rebase). Fail closed: a missing family row denies.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- New tests in `crates/kernel/chio-kernel/src/kernel/tests/family_cap.rs`: `family_cap_denies_child_when_siblings_exhaust_parent`, `family_cap_reconcile_down_releases_co_debit`, `family_cap_capture_after_restart_does_not_replenish`, `family_cap_missing_family_row_denies`.
- SQLite atomicity test in `crates/platform/chio-store-sqlite/src/admission_operation_store_tests/family_cap.rs` proves child hold and family co-debit commit or roll back together.
- `cargo test -p chio-kernel family_cap` and `cargo test -p chio-store-sqlite family_cap` pass; the schema slot appears in the ledger lock file.
- PR-CARRY-FORWARD rows for #957 that this covers are marked with this item ID.

## Log
- 2026-10-09T04:51:58Z connor: created
