---
id: "WORK-W2.2b"
title: "W2.2: durable bilateral delivery intent"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-W2.2a"]
paths: ["crates/kernel/chio-kernel/src/kernel/admission_coordinator/federation_context.rs", "crates/platform/chio-control-plane/src/work/cosign.rs", "crates/platform/chio-control-plane/src/work/transport.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 16.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Plans and specs (landed by WORK-SLICE-C.1): `docs/superpowers/plans/2026-10-03-work-runtime.md`, `2026-10-03-work-owner-services.md`, `2026-10-03-work-developer-surface.md`; specs `docs/superpowers/specs/2026-10-03-work-runtime-design.md`, `work-owner-services-design.md`, `work-developer-surface-design.md`, `agentic-work-kernel-design.md`; real constructor inventory in `docs/research/work-abstraction/INTEGRATION.md` (WORK-W1.0). `WorkViewV1` reports LocalOnly, Pending or Complete. Security review required (kernel federation context).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- The separate-process kill-and-reopen test in `work_peer.rs` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
