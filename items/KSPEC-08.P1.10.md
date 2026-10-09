---
id: "KSPEC-08.P1.10"
title: "Stop receipt metadata `chio_runtime.stop` with retryable_after_resume tied to M20 (S15)"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["KSPEC-03.P1.5", "KSPEC-08.P1.4"]
paths: ["crates/kernel/chio-kernel/src/kernel/responses/deny_responses.rs", "crates/kernel/chio-kernel/src/kernel/mod.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-1 (KSPEC-08 phase 1: KDEF-D2, N22, N23; durable restart-safe stop with an allocated schema slot; reachable from the process-host socket and the CLI). Spec: `docs/superpowers/specs/2026-10-04-durable-stop-epoch-design.md` (rule numbers S1 to S38 below refer to it). KSPEC-08 rule S15 ties `retryable_after_resume` to the M20 identity disposition (KERN-2), so this lands after KSPEC-03.P1.5. CT-WIRE: the metadata key is part of the receipt freeze list.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- The "Identity disposition per path (R-8-02)" cases assert `retryable_after_resume == (identity_disposition == Reusable)`; no tombstone is written on a tier-1 denial.

## Log
- 2026-10-09T04:51:58Z connor: created
