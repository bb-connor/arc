---
id: "WORK-SLICE-DL.2"
title: "Delta: store successors and the projection-kind union"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-SLICE-DL.1", "UR-G0-LEDGER.4", "UR-G0-COLLIDE.2"]
paths: ["crates/platform/chio-store-sqlite/src/admission_operation_store/unknown_release.rs", "crates/platform/chio-store-sqlite/src/admission_operation_store/contractual_resolution.rs", "crates/platform/chio-store-sqlite/src/admission_operation_store/contractual_resolution_read.rs", "crates/platform/chio-store-sqlite/src/admission_operation_unknown_release.sql", "crates/platform/chio-store-sqlite/src/admission_operation_capture_waiver.sql", "crates/platform/chio-store-sqlite/src/budget_store/payment_journal.rs", "crates/platform/chio-store-sqlite/src/serving_owner/global_commit_chain/payment.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method: #1173 (ref `origin/work/verifiable-work-session-20261003`, head cafdc970e) is split by path, not by commit. Diff against its real PR base 75d679670 (not `git merge-base`, which picks the criss-cross base and inflates the diff to 26,621 files); the PR changes 6,637 files. Bring the slice's paths over with `git checkout cafdc970e -- <paths>` onto `integration/beta-next`, then repair against #1160. The slice manifest from WORK-SLICE-0.1 (`docs/research/work-abstraction/SLICES.json`) is the authoritative path list. Slice delta (unknown-payment release, capture waiver, journal overlay, funded work; after CT-SETTLE; off the success-test path). Decision gates: D1 and D2 (parked UR-D1, UR-D2). Collision rider (G0.2): #1173's admission v35/v36 and the `payment_resolution` kind become two symbolic admission slots and a registry append through the ledger lock; the CHECK list then contains both `security_participant_checkpoint` and `payment_resolution`. The effective payment journal (`budget_store/payment_journal.rs:51-78`) overlays the unknown-release or waiver successor and refuses when both exist. Small registration edits in `admission_operation_store.rs`, `schema.rs`, `participant.rs` and `projection.rs` are expected; list them.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Renamed schema vectors and `cargo test -p chio-store-sqlite admission_operation` pass; the projection-kind registry test passes.

## Log
- 2026-10-09T04:51:58Z connor: created
