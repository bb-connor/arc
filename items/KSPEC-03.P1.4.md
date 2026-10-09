---
id: "KSPEC-03.P1.4"
title: "Fix KDEF-N2, N28 and N29: release after receipt commit, no deny on durable-return error, recorded release outcomes"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["KSPEC-03.P1.3"]
paths: ["crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs", "crates/kernel/chio-kernel/src/kernel/evaluation/nested_flow_evaluation.rs", "crates/kernel/chio-kernel/src/kernel/evaluation/return_recording.rs", "crates/kernel/chio-kernel/src/kernel/validation.rs", "crates/kernel/chio-kernel/src/kernel/security_dispatch.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-2 (KSPEC-03 phase 1: KDEF-D1, N2, N28, N29, together with the M20 identity-disposition delta; one train batch because KSPEC-08 rule S15 ties `retryable_after_resume` to M20). Spec: `docs/superpowers/specs/2026-10-04-typed-reservations-design.md` (KSPEC-03). N2: `outcome.record_released()?` runs before finalization (`async_evaluation_core.rs:1761`, `nested_flow_evaluation.rs:1505`); record `Released` only after the receipt commit. N28: in the `return_recording.rs` error arm build no `Deny`; return the error and enqueue reconciliation (rule 25). N29: turn the discards at `validation.rs:1736,1750` into recorded `release_outcome`s (rule 27); also decide the pre-dispatch MustPrepay discards at 2499 and 2506 (fix or allowlist with expiry for KDEF-N4).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Tests "failed durable return writes no receipts.db record" and "capture error after execution leaves the authorization open with `release_outcome: not_released`"; a mutation moving `record_released` earlier fails the suite.

## Log
- 2026-10-09T04:51:58Z connor: created
