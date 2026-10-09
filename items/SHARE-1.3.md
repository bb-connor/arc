---
id: "SHARE-1.3"
title: "Durable sibling-share registry (restart never replenishes)"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["SHARE-1.1", "UR-G0-LEDGER.2", "UR-G0-LEDGER.4"]
paths: ["crates/kernel/chio-kernel/src/kernel/sibling_registry.rs", "crates/kernel/chio-kernel/src/kernel/tests/sibling_registry.rs", "crates/platform/chio-store-sqlite/src/admission_operation_store/sibling_registry.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: SHARE-1 ("plus a durable sibling registry"); KERNEL "owners still to be assigned: the durable sibling-share registry" (this item owns it). Today `crates/kernel/chio-kernel/src/kernel/kernel_struct.rs` keeps `reserved_sibling_shares: Mutex<HashMap<String, ReservedSiblingShare>>` in memory (around line 808), and its own comment notes restart behaviour; `crates/kernel/chio-kernel/src/kernel/reconciliation.rs` and `construction.rs` use it. Move the registry into the durable admission store with a ledger-lock schema slot, keep the existing fail-closed admission semantics, and rebuild the in-memory view from the store at startup. Coordinate edits to `kernel_struct.rs`, `construction.rs` and `reconciliation.rs` by adding the minimal hook lines there (list them in the PR) because other kernel items lease those files.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `crates/kernel/chio-kernel/src/kernel/tests/sibling_registry.rs`: `sibling_share_survives_restart`, `sibling_cannot_be_admitted_against_parent_after_restart`, `released_share_is_not_double_released_after_restart`.
- `cargo test -p chio-kernel sibling_registry` and `cargo test -p chio-store-sqlite sibling` pass; schema slot recorded in the ledger lock.

## Log
- 2026-10-09T04:51:58Z connor: created
