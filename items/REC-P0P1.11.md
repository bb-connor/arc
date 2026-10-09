---
id: "REC-P0P1.11"
title: "Store participant-state, tool-outcome and serving-owner conflicts"
severity: "P2"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["REC-P0P1.9"]
paths: ["crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/**", "crates/platform/chio-store-sqlite/src/admission_operation_store/raw_custody_liability*", "crates/platform/chio-store-sqlite/src/admission_operation_store/tool_outcome_liability*", "crates/platform/chio-store-sqlite/src/admission_operation_store/commit_chain.rs", "crates/platform/chio-store-sqlite/src/admission_operation_store/projection/**", "crates/platform/chio-store-sqlite/src/admission_operation_store/participant.rs", "crates/platform/chio-store-sqlite/src/admission_operation_store/store.rs", "crates/platform/chio-store-sqlite/src/tool_outcome_store*.rs", "crates/platform/chio-store-sqlite/src/serving_owner/**", "crates/platform/chio-store-sqlite/src/security_state/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method (applies to every REC-P0P1 slice): do not run `git rebase`. Re-land from the frozen #1179 source `f217de1fb` (PR head; the roadmap pin 491bd01b5 is stale) onto `integration/beta-next` by path: `git checkout f217de1fb -- <slice globs>`, then repair against #1160's code, and record the slice's source-manifest digest in `docs/architecture/recoverable-agent-runtime/implementation/REBASE-MANIFEST.json` (created by REC-P0P1.0). Keep each slice compiling: new kernel trait methods land with fail-closed default bodies (#1160 precedent `store.rs:874`); `recovery_authority()` returns `None` until the store slices land. Never hand-merge `_generated` files (REC-P0P1.17 regenerates). Roadmap Lane REC requirements this lane must meet: rebase onto #1160's paged sweep rather than porting the old loop; adopt CT-SETTLE and the KSPEC-08 stop chain (KDEF-N24); adopt process ABI v4 (KDEF-N13) and the cage port (KDEF-N16); fix KDEF-N15 (wall-clock time in authority evidence); fix every open P1; take schema slots through the ledger lock; regenerate the SDKs. The #1179 rebase is one of the two riskiest pieces in the roadmap and gets the earliest prototype. The largest hand-written conflict group (store, 28 files). Take #1160's version of anything it already fixed; port only recovery behaviour. #1179 `STATUS.md` records 401 strict store clippy errors today.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-store-sqlite` passes; `cargo clippy -p chio-store-sqlite --all-targets -- -D warnings` clean.

## Log
- 2026-10-09T04:51:58Z connor: created
