---
id: "KSPEC-03.P1.3"
title: "KernelEvidence latch, evidence slots, supervised flusher, append-outcome-unknown"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["KSPEC-03.P1.2"]
paths: ["crates/kernel/chio-kernel/src/kernel/post_effect_evidence.rs", "crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-2 (KSPEC-03 phase 1: KDEF-D1, N2, N28, N29, together with the M20 identity-disposition delta; one train batch because KSPEC-08 rule S15 ties `retryable_after_resume` to M20). Spec: `docs/superpowers/specs/2026-10-04-typed-reservations-design.md` (KSPEC-03). Rules 16 to 18 and 28, and the `chio_runtime.post_effect_fault` receipt metadata key (CT-WIRE freeze list). Hook lines in `construction.rs` and `dispatch.rs` are leased by KSPEC-08.P1.4; coordinate minimal edits after it lands.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Loom: latch against new dispatch and single-flight flusher; DST `AppendTimeoutThenLateCommit`; slot exhaustion denies with `post_effect_evidence_capacity`.

## Log
- 2026-10-09T04:51:58Z connor: created
