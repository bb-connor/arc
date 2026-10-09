---
id: "REC-P0P1.Q"
title: "Re-qualify REC-P0 and REC-P1 (hosted run plus Linux acceptance)"
severity: "P2"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["REC-P0P1.4", "REC-P0P1.7", "REC-P0P1.8", "REC-P0P1.12", "REC-P0P1.15a", "REC-P0P1.15b", "REC-P0P1.17", "REC-P0P1.18", "KDEF-GT1"]
paths: ["docs/architecture/recoverable-agent-runtime/implementation/qualification/p0p1-*.json"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method (applies to every REC-P0P1 slice): do not run `git rebase`. Re-land from the frozen #1179 source `f217de1fb` (PR head; the roadmap pin 491bd01b5 is stale) onto `integration/beta-next` by path: `git checkout f217de1fb -- <slice globs>`, then repair against #1160's code, and record the slice's source-manifest digest in `docs/architecture/recoverable-agent-runtime/implementation/REBASE-MANIFEST.json` (created by REC-P0P1.0). Keep each slice compiling: new kernel trait methods land with fail-closed default bodies (#1160 precedent `store.rs:874`); `recovery_authority()` returns `None` until the store slices land. Never hand-merge `_generated` files (REC-P0P1.17 regenerates). Roadmap Lane REC requirements this lane must meet: rebase onto #1160's paged sweep rather than porting the old loop; adopt CT-SETTLE and the KSPEC-08 stop chain (KDEF-N24); adopt process ABI v4 (KDEF-N13) and the cage port (KDEF-N16); fix KDEF-N15 (wall-clock time in authority evidence); fix every open P1; take schema slots through the ledger lock; regenerate the SDKs. The #1179 rebase is one of the two riskiest pieces in the roadmap and gets the earliest prototype. Run a hosted CI run on the merged slice set and Linux acceptance on the build host. Also triage the remaining committed open items: the hosted "actual Process admitted-return Source test" failure (#1179 `STATUS.md:262-271`) and the reader P1 in an isolated candidate (`STATUS.md:196-199`). The Kani 0.68.0 `catch_unwind` incompatibility (49 proof obligations) is external (parked UR-PK-KANI). Do not modify the P5/P6 seals.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Hosted run passes; `python3 scripts/verify-recovery-qualification.py` passes; a qualification record is committed.

## Log
- 2026-10-09T04:51:58Z connor: created
