---
id: "WORK-W1.5a"
title: "W1.5a: acceptance and all_success joins (no recovery)"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-W1.4b"]
paths: ["crates/platform/chio-control-plane/src/work/acceptance.rs", "crates/platform/chio-control-plane/src/work/joins.rs", "crates/platform/chio-control-plane/tests/work_acceptance.rs", "crates/platform/chio-control-plane/tests/work_joins.rs", "crates/platform/chio-store-sqlite/src/work_graph_store.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Plans and specs (landed by WORK-SLICE-C.1): `docs/superpowers/plans/2026-10-03-work-runtime.md`, `2026-10-03-work-owner-services.md`, `2026-10-03-work-developer-surface.md`; specs `docs/superpowers/specs/2026-10-03-work-runtime-design.md`, `work-owner-services-design.md`, `work-developer-surface-design.md`, `agentic-work-kernel-design.md`; real constructor inventory in `docs/research/work-abstraction/INTEGRATION.md` (WORK-W1.0). Roadmap correction: W1.5 split into a half that needs no recovery (this) and one that does (W1.5b). The evaluator's signed acceptance or rejection is recorded (G4/G5 claim `detect_only`).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `decision_binds_exact_artifact_procedure_and_evaluator`, `unpaid_evaluator_is_receipted_work`, `all_success_requires_verified_parents`, `join_draft_publication_is_atomic` pass.

## Log
- 2026-10-09T04:51:58Z connor: created
