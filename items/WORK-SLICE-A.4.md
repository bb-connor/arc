---
id: "WORK-SLICE-A.4"
title: "Alpha: checked output and zero-charge outcome authority, without #1173's sweep edit"
severity: "P2"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-SLICE-A.3", "KSPEC-03.P1.4"]
paths: ["crates/kernel/chio-kernel/src/kernel/output_guard.rs", "crates/kernel/chio-kernel/src/kernel/delivery_contract.rs", "crates/kernel/chio-kernel/src/kernel/evaluation/delivery_preparation.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal/output_verdict.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal/receipt_content.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/outcome_authority.rs", "crates/kernel/chio-kernel/src/kernel/tests/durable_admission/checked_output.rs", "crates/kernel/chio-kernel/tests/durable_admission_sqlite/checked_output.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method: #1173 (ref `origin/work/verifiable-work-session-20261003`, head cafdc970e) is split by path, not by commit. Diff against its real PR base 75d679670 (not `git merge-base`, which picks the criss-cross base and inflates the diff to 26,621 files); the PR changes 6,637 files. Bring the slice's paths over with `git checkout cafdc970e -- <paths>` onto `integration/beta-next`, then repair against #1160. The slice manifest from WORK-SLICE-0.1 (`docs/research/work-abstraction/SLICES.json`) is the authoritative path list. Slice alpha (execution evidence and checked output; lands right after Gate 0; drops #1173's own sweep edit in favour of #1160's classifier). #1173 special-cased `KernelError::GuardDenied` in the sweep (old `recovery.rs` about 338-356); #1160's `recovery/failure.rs::classify` already maps GuardDenied, FindingDenied, CapabilityRevoked and DelegationChainRevoked to `OutputDenied`, deferred by `defer_admission_recovery`. Keep #1160's sweep and discard #1173's branch. `terminal.rs` hook lines are shared with KSPEC-03/04 and REC items; land after KSPEC-03.P1.4.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- The 10 unit tests (for example `checked_output_first_rejection_survives_terminal_projection_recovery`), the 3 sqlite tests (for example `retained_zero_charge_denial_recovers_after_output_authority_expires`) and new `checked_output_denial_is_deferred_by_paged_sweep_classifier` pass.

## Log
- 2026-10-09T04:51:58Z connor: created
