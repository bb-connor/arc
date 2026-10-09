---
id: "REC-P5a"
title: "Cage port onto #1160's cage crates (KDEF-N16)"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["REC-P0P1.Q"]
paths: ["crates/security/chio-cage/**", "crates/security/chio-cage-plan/**", "crates/security/chio-cage-init/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method (applies to every REC-P0P1 slice): do not run `git rebase`. Re-land from the frozen #1179 source `f217de1fb` (PR head; the roadmap pin 491bd01b5 is stale) onto `integration/beta-next` by path: `git checkout f217de1fb -- <slice globs>`, then repair against #1160's code, and record the slice's source-manifest digest in `docs/architecture/recoverable-agent-runtime/implementation/REBASE-MANIFEST.json` (created by REC-P0P1.0). Keep each slice compiling: new kernel trait methods land with fail-closed default bodies (#1160 precedent `store.rs:874`); `recovery_authority()` returns `None` until the store slices land. Never hand-merge `_generated` files (REC-P0P1.17 regenerates). Roadmap Lane REC requirements this lane must meet: rebase onto #1160's paged sweep rather than porting the old loop; adopt CT-SETTLE and the KSPEC-08 stop chain (KDEF-N24); adopt process ABI v4 (KDEF-N13) and the cage port (KDEF-N16); fix KDEF-N15 (wall-clock time in authority evidence); fix every open P1; take schema slots through the ledger lock; regenerate the SDKs. The #1179 rebase is one of the two riskiest pieces in the roadmap and gets the earliest prototype. KDEF-N16: #1179 edits cage files that #1160 deleted (`launch/linux_parts/part_01_sections/bootstrap.inc`, `linux_parts/part_02.rs`, `lib_parts/part_01.rs`); #1160 moved internals to `chio-cage-plan` and `chio-cage-init`. Port #1179's new APIs (`base_plan_digest`, `ObservedCageExit`, `try_wait_verified`, `launch/linux/preparation.rs`, `bin/chio-confined-reader.rs`) onto the new layout.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `bash crates/security/chio-cage/scripts/check-linux-enforcement.sh` passes on the Linux build host; `python3 scripts/check-cage-all-target-inventory.py` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
