---
id: "REC-P0P1.7"
title: "Kernel native participants and return custody"
severity: "P2"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["REC-P0P1.5"]
paths: ["crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_egress/**", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_output.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/process_return_participant.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/return_context/**", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/security_release/recovery.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/compensated_denial.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/output_retention.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/collection_context.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 16.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method (applies to every REC-P0P1 slice): do not run `git rebase`. Re-land from the frozen #1179 source `f217de1fb` (PR head; the roadmap pin 491bd01b5 is stale) onto `integration/beta-next` by path: `git checkout f217de1fb -- <slice globs>`, then repair against #1160's code, and record the slice's source-manifest digest in `docs/architecture/recoverable-agent-runtime/implementation/REBASE-MANIFEST.json` (created by REC-P0P1.0). Keep each slice compiling: new kernel trait methods land with fail-closed default bodies (#1160 precedent `store.rs:874`); `recovery_authority()` returns `None` until the store slices land. Never hand-merge `_generated` files (REC-P0P1.17 regenerates). Roadmap Lane REC requirements this lane must meet: rebase onto #1160's paged sweep rather than porting the old loop; adopt CT-SETTLE and the KSPEC-08 stop chain (KDEF-N24); adopt process ABI v4 (KDEF-N13) and the cage port (KDEF-N16); fix KDEF-N15 (wall-clock time in authority evidence); fix every open P1; take schema slots through the ledger lock; regenerate the SDKs. The #1179 rebase is one of the two riskiest pieces in the roadmap and gets the earliest prototype. These admission-coordinator files are shared with WORK slice alpha (WORK-SLICE-A.3/A.4) and KSPEC-08.P1.4; path leases serialize them. Small hook edits in `kernel/validation.rs` and `kernel/evaluation/evaluation_helpers.rs` are allowed; list them.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-kernel --lib admission_coordinator` and clippy pass.

## Log
- 2026-10-09T04:51:58Z connor: created
