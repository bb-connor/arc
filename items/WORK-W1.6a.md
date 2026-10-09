---
id: "WORK-W1.6a"
title: "W1.6a: command index, apply and query (pre-dispatch, no recovery)"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-W1.5a"]
paths: ["crates/kernel/chio-runtime-core/src/store/sqlite/work_commands.rs", "crates/platform/chio-control-plane/src/work/dispatch.rs", "crates/platform/chio-control-plane/src/work/query.rs", "crates/platform/chio-control-plane/tests/work_recovery.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Plans and specs (landed by WORK-SLICE-C.1): `docs/superpowers/plans/2026-10-03-work-runtime.md`, `2026-10-03-work-owner-services.md`, `2026-10-03-work-developer-surface.md`; specs `docs/superpowers/specs/2026-10-03-work-runtime-design.md`, `work-owner-services-design.md`, `work-developer-surface-design.md`, `agentic-work-kernel-design.md`; real constructor inventory in `docs/research/work-abstraction/INTEGRATION.md` (WORK-W1.0). Lost acknowledgement after retention, after a D1 mutation and during interleaved A/B extension; query by original ID before a handle exists; blocked-provider and shutdown tests.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- The listed cases pass in `work_recovery.rs` (pre-dispatch subset).

## Log
- 2026-10-09T04:51:58Z connor: created
