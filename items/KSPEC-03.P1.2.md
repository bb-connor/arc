---
id: "KSPEC-03.P1.2"
title: "Wire the obligation into both evaluators (KDEF-D1)"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["KSPEC-03.P1.1"]
paths: ["crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs", "crates/kernel/chio-kernel/src/kernel/evaluation/nested_flow_evaluation.rs", "crates/kernel/chio-kernel/src/kernel/evaluation/return_recording.rs", "crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 16.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-2 (KSPEC-03 phase 1: KDEF-D1, N2, N28, N29, together with the M20 identity-disposition delta; one train batch because KSPEC-08 rule S15 ties `retryable_after_resume` to M20). Spec: `docs/superpowers/specs/2026-10-04-typed-reservations-design.md` (KSPEC-03). KDEF-D1 changed shape on #1160: the non-durable disarm is now in `return_recording.rs:30` (`record_evaluation_return`, `admission = None` branch) and still runs before `finalize_ordinary_recovery_response` (`async_evaluation_core.rs:1975`); transport-failure arms disarm then build receipts fallibly (async 1798, 1829, 1863, 1895; nested 1579, 1616, 1650, 1682). Remove the non-durable disarm and the eight transport-arm disarms; contain `Drop` (rule 24).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Proptest `crates/kernel/chio-kernel/src/kernel/tests/drop_guard_proptest.rs`: {failing post-effect step} x {SideEffecting read-only, Monetary, Off} x {drop, return}; every case ends in exactly one terminal receipt, fault receipt, or buffered record plus latch.

## Log
- 2026-10-09T04:51:58Z connor: created
