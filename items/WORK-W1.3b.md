---
id: "WORK-W1.3b"
title: "W1.3: semantic-generation basis (after REC)"
severity: "P2"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-W1.3a", "REC-P3"]
paths: ["crates/platform/chio-control-plane/src/work/profiles.rs", "crates/platform/chio-control-plane/tests/work_profiles.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 5.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Plans and specs (landed by WORK-SLICE-C.1): `docs/superpowers/plans/2026-10-03-work-runtime.md`, `2026-10-03-work-owner-services.md`, `2026-10-03-work-developer-surface.md`; specs `docs/superpowers/specs/2026-10-03-work-runtime-design.md`, `work-owner-services-design.md`, `work-developer-surface-design.md`, `agentic-work-kernel-design.md`; real constructor inventory in `docs/research/work-abstraction/INTEGRATION.md` (WORK-W1.0). Wire `SemanticPackageV1` (#1179 `chio-security-types/src/semantic/package.rs:110`). `SemanticDeploymentBindingV1` exists in no code: define it here or drop it from the plan (record which).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Profile tests cover a live semantic generation and a stale one.

## Log
- 2026-10-09T04:51:58Z connor: created
