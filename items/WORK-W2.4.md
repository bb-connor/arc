---
id: "WORK-W2.4"
title: "W2.4: lost-reply recovery join (after REC)"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-W1.6b", "WORK-W2.2b", "REC-EXIT"]
paths: ["crates/platform/chio-control-plane/src/work/recovery.rs", "crates/platform/chio-control-plane/src/work/projection.rs", "crates/platform/chio-control-plane/tests/work_recovery_join.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 16.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Plans and specs (landed by WORK-SLICE-C.1): `docs/superpowers/plans/2026-10-03-work-runtime.md`, `2026-10-03-work-owner-services.md`, `2026-10-03-work-developer-surface.md`; specs `docs/superpowers/specs/2026-10-03-work-runtime-design.md`, `work-owner-services-design.md`, `work-developer-surface-design.md`, `agentic-work-kernel-design.md`; real constructor inventory in `docs/research/work-abstraction/INTEGRATION.md` (WORK-W1.0). Roadmap: W2.4 after REC; success-test criterion (c) (a lost reply exercised during the live run is recovered by original identity with no second dispatch).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `refusal_to_authorized_progress` (LC03), `policy_reload_preserves_commitments` (LC04), `dependency_category_is_enforced` pass.

## Log
- 2026-10-09T04:51:58Z connor: created
