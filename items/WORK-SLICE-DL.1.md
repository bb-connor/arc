---
id: "WORK-SLICE-DL.1"
title: "Delta: kernel payment successors on CT-SETTLE"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-SETTLE.3", "WORK-SLICE-A.4", "SHARE-4.4"]
paths: ["crates/kernel/chio-kernel/src/payment/journal.rs", "crates/kernel/chio-kernel/src/payment/unknown_release.rs", "crates/kernel/chio-kernel/src/payment/contractual_resolution.rs", "crates/kernel/chio-kernel/src/payment/contractual_resolution_record.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal_payment.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal/payment_receipt.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/before_dispatch_compensation.rs", "crates/kernel/chio-kernel/tests/contractual_capture_waiver_signatures.rs", "crates/kernel/chio-kernel/tests/durable_admission_sqlite/unknown_release.rs", "crates/kernel/chio-kernel/tests/durable_admission_sqlite/contractual_resolution.rs", "crates/kernel/chio-kernel/tests/durable_admission_sqlite/payment_acknowledgement.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 16.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method: #1173 (ref `origin/work/verifiable-work-session-20261003`, head cafdc970e) is split by path, not by commit. Diff against its real PR base 75d679670 (not `git merge-base`, which picks the criss-cross base and inflates the diff to 26,621 files); the PR changes 6,637 files. Bring the slice's paths over with `git checkout cafdc970e -- <paths>` onto `integration/beta-next`, then repair against #1160. The slice manifest from WORK-SLICE-0.1 (`docs/research/work-abstraction/SLICES.json`) is the authoritative path list. Slice delta (unknown-payment release, capture waiver, journal overlay, funded work; after CT-SETTLE; off the success-test path). Decision gates: D1 and D2 (parked UR-D1, UR-D2). `payment/journal.rs` adds `PaymentReleaseAuthorityKind::{MutuallyAgreedUnknown, ContractualCaptureWaiver}` (#1160 has only `PreDispatchNoEffect`, `TransportNotAccepted`, `ContractualZeroCharge`). Journal overlay read before finalization; a hold is a classified per-item deferral in #1160's sweep; signer rotation follows CT-SETTLE.3 (#1173 currently refuses at `unknown_release.rs:499,562`). Activate CT-SETTLE.2's M7a and M7b vectors. Follows SHARE-4.4 (which moves rail clients out of `payment.rs`).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `mutual_release_*` (4), `capture_waiver_*` (3) and new `hold_never_blocks_cosigned_successor` pass; CT-SETTLE.2 harness reports zero pending vectors.

## Log
- 2026-10-09T04:51:58Z connor: created
