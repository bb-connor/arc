---
id: "CT-SETTLE.2"
title: "Settlement composition conformance harness on #1160's paged sweep"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-SETTLE.1"]
paths: ["crates/kernel/chio-kernel/tests/durable_admission_sqlite/recovery_sweep/settlement_composition.rs", "crates/kernel/chio-kernel/tests/durable_admission_sqlite/recovery_sweep/settlement_support.rs", "crates/kernel/chio-kernel/tests/durable_admission_sqlite/recovery_sweep.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: CT-SETTLE ("implemented on #1160's paged startup sweep"). Sources: #1174 cross-spec decision 4 ("Reservation classes", `docs/superpowers/specs/2026-10-04-ftl-lessons-program-design.md:289-294`) and spec 9 (`2026-10-04-pure-admission-machine-design.md`): M7a (528-553: only `ReleaseAuthorized` in `Terminal(OutcomeUnknownAfterDispatch)` with a `Frozen` hold releases money; `Released` only on acknowledgement; per-attempt keys), M7b (554-558: `CaptureWaiverAuthorized` only in `Finalizing` with a known return and a reversible hold with a pending capture; illegal on unknown outcome), M11a (605-622: delivery refusal never decides money; an `Open` positive hold is retained for the payment owner's successor), R-9-05 (24, 1214: read the journal stage first; `Final` is recognized with no new capture, release or refund; `InFlight` completes under its original identity; tests at 1003-1009). #1160's sweep: `crates/kernel/chio-kernel/src/kernel/admission_coordinator/recovery.rs:124-201`, `recovery/page.rs`, `recovery/failure.rs::classify`, `recovery/deferral.rs` (`AdmissionRecoveryDeferralV1`, kinds at `admission_operation/recovery.rs:99-109`). Build a reusable harness over a real SQLite authority (reuse `SweepClock` and `Serving`) that loads `spec/vectors/settle/v1`. REC slices and WORK slice delta extend it. Pending vectors are counted: the harness fails if a pending vector is activated without an implementation or an implemented one stays pending. Existing regression to keep: `sqlite_replaced_signer_defers_its_operation_and_recovers_the_next` (`recovery_sweep/signer_identity.rs:165`).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-kernel --test durable_admission_sqlite recovery_sweep::settlement_composition` passes with: `sweep_defers_classified_item_and_completes_the_rest`, `final_journal_recognized_without_new_settlement`, `inflight_capture_completes_under_original_identity_after_restart`, `open_positive_hold_retained_on_delivery_refusal`, `signer_mismatch_defers_without_aborting_startup`, `pending_successor_vectors_are_declared`.

## Log
- 2026-10-09T04:51:58Z connor: created
