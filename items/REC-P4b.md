---
id: "REC-P4b"
title: "Durable knowledge: store and control plane"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["REC-P4a", "UR-G0-LEDGER.4"]
paths: ["crates/platform/chio-store-sqlite/src/admission_operation_store/knowledge.rs", "crates/platform/chio-store-sqlite/src/admission_operation_store/knowledge/**", "crates/platform/chio-control-plane/src/knowledge.rs", "crates/platform/chio-control-plane/src/knowledge/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 16.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method (applies to every REC-P0P1 slice): do not run `git rebase`. Re-land from the frozen #1179 source `f217de1fb` (PR head; the roadmap pin 491bd01b5 is stale) onto `integration/beta-next` by path: `git checkout f217de1fb -- <slice globs>`, then repair against #1160's code, and record the slice's source-manifest digest in `docs/architecture/recoverable-agent-runtime/implementation/REBASE-MANIFEST.json` (created by REC-P0P1.0). Keep each slice compiling: new kernel trait methods land with fail-closed default bodies (#1160 precedent `store.rs:874`); `recovery_authority()` returns `None` until the store slices land. Never hand-merge `_generated` files (REC-P0P1.17 regenerates). Roadmap Lane REC requirements this lane must meet: rebase onto #1160's paged sweep rather than porting the old loop; adopt CT-SETTLE and the KSPEC-08 stop chain (KDEF-N24); adopt process ABI v4 (KDEF-N13) and the cage port (KDEF-N16); fix KDEF-N15 (wall-clock time in authority evidence); fix every open P1; take schema slots through the ledger lock; regenerate the SDKs. The #1179 rebase is one of the two riskiest pieces in the roadmap and gets the earliest prototype. The store knowledge tree is 70 files (18.9k lines); exclude `knowledge/confinement/**` (REC-P5b). Takes the knowledge-encoding schema slot through the ledger lock. Fix KDEF-N15 at `knowledge.rs:61`.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Store and control-plane knowledge tests pass; clock gate passes.

## Log
- 2026-10-09T04:51:58Z connor: created
