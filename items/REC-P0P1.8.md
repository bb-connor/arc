---
id: "REC-P0P1.8"
title: "Terminal finalization with the D2 signing rule (fixes the rotation-wedge P1)"
severity: "P2"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["REC-P0P1.6", "CT-SETTLE.3", "KSPEC-03.P1.4"]
paths: ["crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal/historical_signing.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal/public_delivery.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal/evaluation_contract.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal/semantic.rs", "crates/kernel/chio-kernel/src/kernel/signing_authority.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method (applies to every REC-P0P1 slice): do not run `git rebase`. Re-land from the frozen #1179 source `f217de1fb` (PR head; the roadmap pin 491bd01b5 is stale) onto `integration/beta-next` by path: `git checkout f217de1fb -- <slice globs>`, then repair against #1160's code, and record the slice's source-manifest digest in `docs/architecture/recoverable-agent-runtime/implementation/REBASE-MANIFEST.json` (created by REC-P0P1.0). Keep each slice compiling: new kernel trait methods land with fail-closed default bodies (#1160 precedent `store.rs:874`); `recovery_authority()` returns `None` until the store slices land. Never hand-merge `_generated` files (REC-P0P1.17 regenerates). Roadmap Lane REC requirements this lane must meet: rebase onto #1160's paged sweep rather than porting the old loop; adopt CT-SETTLE and the KSPEC-08 stop chain (KDEF-N24); adopt process ABI v4 (KDEF-N13) and the cage port (KDEF-N16); fix KDEF-N15 (wall-clock time in authority evidence); fix every open P1; take schema slots through the ledger lock; regenerate the SDKs. The #1179 rebase is one of the two riskiest pieces in the roadmap and gets the earliest prototype. Implement CT-SETTLE.3's rule in one place for ordinary finalization and recovery settlement. This closes #1179's "settlement after operator rotation wedges the startup sweep" P1 on the paged sweep (#1179 `STATUS.md:184-191,246-256` describes current-signer regressions timing out in repeated reconciliation). `terminal.rs` is also edited by KSPEC-03 and KSPEC-04 items; follow their order.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-kernel --test durable_admission_sqlite recovery_sweep::signer_identity` passes; `rotated_signer_finalizes_with_original_identity_bound` is activated and passes; new `rotation_never_wedges_startup_after_restart` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
