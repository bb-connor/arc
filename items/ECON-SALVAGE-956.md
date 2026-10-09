---
id: "ECON-SALVAGE-956"
title: "Salvage #956 approval binding: VerifiedApproval, signed settlement terms, single use"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["UR-LEDGER-CARRY"]
paths: ["crates/economy/chio-settle/src/approval_witness.rs", "crates/economy/chio-settle/src/payments.rs", "crates/economy/chio-settle/src/payments_tests.rs", "crates/economy/chio-settle/src/lib.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: section 7 (#956 to #959: salvage, then close). From PR #956 (ref `origin/bac-541-c2-approval-binding`): the unforgeable `VerifiedApproval` witness (`crates/economy/chio-settle/src/approval_witness.rs`), settlement terms inside the signed intent, single use keyed on request and intent, and raw builders made `pub(crate)`. First compare with post-#1160 main, which already has a kernel-side `VerifiedApproval` (`crates/kernel/chio-kernel/src/kernel/governed_validation.rs`, `admission_coordinator.rs`): port only what main lacks and do not create a second competing type. Address the 27 ledger requirements with `landing_pr` 956 (see `docs/operations/pr-carry-forward.json`).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Tests port or add: forging a `VerifiedApproval` outside the crate does not compile (trybuild or visibility test), settlement terms outside the signed intent are rejected, replaying the same request plus intent is rejected.
- `cargo test -p chio-settle` passes; every #956 row in PR-CARRY-FORWARD is marked repaired, adjudicated duplicate-of-main, or open with reason.

## Log
- 2026-10-09T04:51:58Z connor: created
