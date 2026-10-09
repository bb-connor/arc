---
id: "WORK-W1.2a"
title: "W1.2: qualified D1 delegation store (schema slot)"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-W1.0", "UR-G0-LEDGER.4", "UR-G0-COLLIDE.2"]
paths: ["crates/platform/chio-workflow/src/delegation/transition.rs", "crates/platform/chio-workflow/src/delegation/mod.rs", "crates/platform/chio-workflow/src/delegation/store.rs", "crates/platform/chio-store-sqlite/src/delegation_store.rs", "crates/platform/chio-store-sqlite/src/delegation_store/**", "crates/platform/chio-store-sqlite/tests/work_delegation_authority.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 16.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Plans and specs (landed by WORK-SLICE-C.1): `docs/superpowers/plans/2026-10-03-work-runtime.md`, `2026-10-03-work-owner-services.md`, `2026-10-03-work-developer-surface.md`; specs `docs/superpowers/specs/2026-10-03-work-runtime-design.md`, `work-owner-services-design.md`, `work-developer-surface-design.md`, `agentic-work-kernel-design.md`; real constructor inventory in `docs/research/work-abstraction/INTEGRATION.md` (WORK-W1.0). New store key and projection kind through the ledger lock (planned name WORK-W1.2). Registration edits in `chio-store-sqlite/src/lib.rs`, `serving_owner.rs` and `serving_owner/global_commit_chain/projection_kinds.rs` are expected; list them.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Stale fence, copied store, concurrent over-allocation, seal replay and expired-history tests pass: `cargo test --locked -p chio-store-sqlite --test work_delegation_authority`.

## Log
- 2026-10-09T04:51:58Z connor: created
