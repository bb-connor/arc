---
id: "REC-P0P1.5"
title: "Kernel recovery types, ports and retained encoding (KDEF-N15 kernel half)"
severity: "P2"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["REC-P0P1.2", "KDEF-CLOCK-GATE", "CT-WORK.1"]
paths: ["crates/kernel/chio-kernel/src/recovery/**", "crates/kernel/chio-kernel/src/admission_operation/store.rs", "crates/kernel/chio-kernel/src/admission_operation/retained_request.rs", "crates/kernel/chio-kernel/src/admission_operation/output_retention.rs", "crates/kernel/chio-kernel/src/admission_operation/native_input_join.rs", "crates/kernel/chio-kernel/src/tool_outcome/retained_encoding*.rs", "crates/kernel/chio-kernel/src/tool_outcome/receipt_signing.rs", "crates/kernel/chio-kernel/src/process_return_custody.rs", "crates/kernel/chio-kernel/src/runtime/recovery_*.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method (applies to every REC-P0P1 slice): do not run `git rebase`. Re-land from the frozen #1179 source `f217de1fb` (PR head; the roadmap pin 491bd01b5 is stale) onto `integration/beta-next` by path: `git checkout f217de1fb -- <slice globs>`, then repair against #1160's code, and record the slice's source-manifest digest in `docs/architecture/recoverable-agent-runtime/implementation/REBASE-MANIFEST.json` (created by REC-P0P1.0). Keep each slice compiling: new kernel trait methods land with fail-closed default bodies (#1160 precedent `store.rs:874`); `recovery_authority()` returns `None` until the store slices land. Never hand-merge `_generated` files (REC-P0P1.17 regenerates). Roadmap Lane REC requirements this lane must meet: rebase onto #1160's paged sweep rather than porting the old loop; adopt CT-SETTLE and the KSPEC-08 stop chain (KDEF-N24); adopt process ABI v4 (KDEF-N13) and the cage port (KDEF-N16); fix KDEF-N15 (wall-clock time in authority evidence); fix every open P1; take schema slots through the ledger lock; regenerate the SDKs. The #1179 rebase is one of the two riskiest pieces in the roadmap and gets the earliest prototype. Move every `refresh_trusted_time(current_unix_timestamp_ms())` onto #1160's fallible clock (`refresh_trusted_time` is fallible at `admission_coordinator.rs:202`; `ChioKernel::authority_clock()` at `kernel/clock.rs:24`); #1179 adds about 78 ambient clock reads in the kernel. Make the recovery control grant require exactly `[Invoke]` (Codex P2 at `ports.rs:338-340`, which uses `contains(Invoke)`). Keep the real port names `RecoveryProcessReservationPort`, `RecoveryProcessOriginPort`, `RecoveryAuthorityPort` (`ports.rs:46,56,76`) exactly as CT-WORK.1 maps them.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-kernel --lib recovery` passes including new `recovery_control_grant_requires_exact_invoke`; `python3 scripts/check-security-clocks.py` passes with no new inventory rows.

## Log
- 2026-10-09T04:51:58Z connor: created
