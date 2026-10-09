---
id: "WORK-W3.2a"
title: "W3: process work transport (chio.work.v1 on the process socket)"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-W2.1a", "REC-P0P1.13"]
paths: ["crates/kernel/chio-process/src/worker.rs", "crates/kernel/chio-process/src/worker/work_transport.rs", "crates/kernel/chio-process/tests/work_transport.rs", "crates/platform/chio-control-plane/src/work/worker_service.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Plans and specs (landed by WORK-SLICE-C.1): `docs/superpowers/plans/2026-10-03-work-runtime.md`, `2026-10-03-work-owner-services.md`, `2026-10-03-work-developer-surface.md`; specs `docs/superpowers/specs/2026-10-03-work-runtime-design.md`, `work-owner-services-design.md`, `work-developer-surface-design.md`, `agentic-work-kernel-design.md`; real constructor inventory in `docs/research/work-abstraction/INTEGRATION.md` (WORK-W1.0). Negotiate `chio.work.v1` alongside `chio.process.v1` on the same socket (CT-ABI.2). Follows REC-P0P1.13 (ABI v4 flip).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test --locked -p chio-process --features worker-server --test work_transport` passes; an old client against a new host refuses explicitly.

## Log
- 2026-10-09T04:51:58Z connor: created
