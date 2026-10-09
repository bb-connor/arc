---
id: "SHARE-1.1"
title: "Consumption ledger design: map the seven counters onto the kernel hold ledger"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["DOCS-1174.1", "SHARE-4.1", "CT-ABI.1"]
paths: ["docs/architecture/CONSUMPTION-LEDGER.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: SHARE-1 ("the kernel hold ledger is the only consumption authority; every other counter becomes a commitment entry or a view, following #1174's sealed-ledger proposal"; "decide what basis-point shares actually bound; today they are declarations only"). Inventory the seven counters with exact code owners on post-#1160 main:
- grant holds: `crates/kernel/chio-kernel/src/budget_store.rs` (`BudgetAuthorizeHoldRequest`, `BudgetCaptureHoldRequest`, `BudgetReconcileHoldRequest`) and the SQLite owner `crates/platform/chio-store-sqlite/src/admission_operation_store/{budget_custody,caller_budget}.rs`;
- aggregate families: `crates/core/chio-core-types/src/capability/token.rs` and `crates/kernel/chio-kernel/src/authority.rs`;
- basis-point shares: `crates/core/chio-core-types/src/capability/{attenuation,validation}.rs`;
- process shares: `crates/kernel/chio-process/src/{types,store}.rs` (`max_processes`, `max_depth`, `max_calls`);
- D1 slots and S1 pools: #1173 slice beta (dynamic delegation and swarm evolution);
- the finding pool: `crates/kernel/chio-kernel/src/finding_pool.rs` and `crates/kernel/chio-swarm-authority/src/finding_pool.rs`;
- in-memory sibling shares: `crates/kernel/chio-kernel/src/kernel/kernel_struct.rs` `reserved_sibling_shares` (line ~808, lost on restart).
Use KSPEC-03's typed reservation ledger (`docs/superpowers/specs/2026-10-04-typed-reservations-design.md`: `Compensable`, `Retained`, `Commitment` entry classes) as the target model. For each counter state: authority (hold ledger) vs commitment entry vs view, durability, restart behaviour, and migration slice. Decide and justify what basis-point shares bound (the doc records the decision; if it needs an owner call, say so explicitly). Boundary: `prevent` for kernel-mediated calls, `planning_status: ready_after_adr` (ADR-0016, CT-ABI).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- CONSUMPTION-LEDGER.md has one row per counter with code owner path, target class, durability, and the SHARE item that migrates it (SHARE-1.2 to SHARE-1.6).
- The basis-point-share decision is stated with a test plan; reviewers from Lane KERNEL sign off in the PR.

## Log
- 2026-10-09T04:51:58Z connor: created
