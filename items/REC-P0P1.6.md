---
id: "REC-P0P1.6"
title: "Sweep integration: historical hold as a classified per-item deferral (CT-SETTLE)"
severity: "P2"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["REC-P0P1.5", "CT-SETTLE.2", "KSPEC-08.P1.6"]
paths: ["crates/kernel/chio-kernel/src/kernel/admission_coordinator/recovery.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/recovery/operation.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/recovery/failure.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/recovery/deferral.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/recovery_runtime.rs", "crates/kernel/chio-kernel/src/admission_operation/recovery.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method (applies to every REC-P0P1 slice): do not run `git rebase`. Re-land from the frozen #1179 source `f217de1fb` (PR head; the roadmap pin 491bd01b5 is stale) onto `integration/beta-next` by path: `git checkout f217de1fb -- <slice globs>`, then repair against #1160's code, and record the slice's source-manifest digest in `docs/architecture/recoverable-agent-runtime/implementation/REBASE-MANIFEST.json` (created by REC-P0P1.0). Keep each slice compiling: new kernel trait methods land with fail-closed default bodies (#1160 precedent `store.rs:874`); `recovery_authority()` returns `None` until the store slices land. Never hand-merge `_generated` files (REC-P0P1.17 regenerates). Roadmap Lane REC requirements this lane must meet: rebase onto #1160's paged sweep rather than porting the old loop; adopt CT-SETTLE and the KSPEC-08 stop chain (KDEF-N24); adopt process ABI v4 (KDEF-N13) and the cage port (KDEF-N16); fix KDEF-N15 (wall-clock time in authority evidence); fix every open P1; take schema slots through the ledger lock; regenerate the SDKs. The #1179 rebase is one of the two riskiest pieces in the roadmap and gets the earliest prototype. #1179's only edit to the old startup loop is `if self.quarantine_unavailable_recovery(&operation, trusted_now_unix_ms)? { continue; }` (old `recovery.rs:295-300`): the `?` aborts the whole sweep on any hold-path error, and the old loop returns a deferred failure so `startup_reconciled` is never set. Drop that loop entirely. Call `quarantine_unavailable_recovery` (`recovery_runtime.rs:714-799`) from `recover_one_admission`'s `Finalizing` arm; a held operation returns a new classified kind `HistoricalAuthorityHeld`, deferred with its durable hold, never a `?` abort. Rewrite `reconcile_recovery_original` (`recovery_runtime.rs:232-318`, KDEF-N20's second classifier) to call the shared per-item step. Holds must not block monetary successors. This slice follows KSPEC-08.P1.6 (which adds the `KernelStopped` deferral kind in the same files).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-kernel --test durable_admission_sqlite recovery_sweep` passes including new `historical_hold_defers_item_and_startup_completes` and `scoped_original_closure_uses_shared_step`; all CT-SETTLE.2 vectors that are not pending pass.

## Log
- 2026-10-09T04:51:58Z connor: created
