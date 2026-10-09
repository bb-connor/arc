---
id: "KSPEC-08.P1.6"
title: "Stop heads load before the sweep: ready_stopped, withheld-output custody, tier-2 CAS predicates"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["KSPEC-08.P1.3", "KSPEC-08.P1.4", "KSPEC-03.P1.4"]
paths: ["crates/kernel/chio-kernel/src/kernel/admission_coordinator/recovery.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/recovery/deferral.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/recovery/failure.rs", "crates/kernel/chio-kernel/src/admission_operation/recovery.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_output.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 16.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-1 (KSPEC-08 phase 1: KDEF-D2, N22, N23; durable restart-safe stop with an allocated schema slot; reachable from the process-host socket and the CLI). Spec: `docs/superpowers/specs/2026-10-04-durable-stop-epoch-design.md` (rule numbers S1 to S38 below refer to it). 
Rules S9, S10, S26. Add `AdmissionRecoveryFailureKind::KernelStopped` as a classified deferral (never fatal) in #1160's paged sweep (`recovery/failure.rs::classify`, `recovery/deferral.rs`). Tier 2 is a predicate inside the existing dispatch-commit and release transactions. KSPEC-04.P1.2 edits the same CAS and must follow this item. CT-SETTLE's sweep rules apply: one sweep owner, classified per-item deferral.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- S8-01: restart with `Finalizing` work gives `ready_stopped`, status answers, and resume releases each withheld output exactly once.
- DST: a stop racing a `DispatchCommitted` CAS resolves to one order; a stale tier 1 is refused by tier 2. `cargo test -p chio-kernel --test durable_admission_sqlite stop` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
