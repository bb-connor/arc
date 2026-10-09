---
id: "REC-P0P1.0"
title: "#1179 re-land charter: slice manifest for every source path"
severity: "P2"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["docs/architecture/recoverable-agent-runtime/implementation/REBASE-MANIFEST.json", "scripts/rec-slice-manifest.py", "scripts/tests/rec-slice-manifest.test.py"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method (applies to every REC-P0P1 slice): do not run `git rebase`. Re-land from the frozen #1179 source `f217de1fb` (PR head; the roadmap pin 491bd01b5 is stale) onto `integration/beta-next` by path: `git checkout f217de1fb -- <slice globs>`, then repair against #1160's code, and record the slice's source-manifest digest in `docs/architecture/recoverable-agent-runtime/implementation/REBASE-MANIFEST.json` (created by REC-P0P1.0). Keep each slice compiling: new kernel trait methods land with fail-closed default bodies (#1160 precedent `store.rs:874`); `recovery_authority()` returns `None` until the store slices land. Never hand-merge `_generated` files (REC-P0P1.17 regenerates). Roadmap Lane REC requirements this lane must meet: rebase onto #1160's paged sweep rather than porting the old loop; adopt CT-SETTLE and the KSPEC-08 stop chain (KDEF-N24); adopt process ABI v4 (KDEF-N13) and the cage port (KDEF-N16); fix KDEF-N15 (wall-clock time in authority evidence); fix every open P1; take schema slots through the ledger lock; regenerate the SDKs. The #1179 rebase is one of the two riskiest pieces in the roadmap and gets the earliest prototype. Facts: #1179's code arrived in one commit (5e16cb912, 1,235 files) and docs and evidence in another (77006b86f, 5,937 files; `p6/` alone is 5,102), so slices are cut by path. A trivial merge-tree against #1160 gives 275 content conflicts, 12 modify/delete and 2 add/add (289 paths); 160 are generated files, leaving 115 hand-written conflicts (store 28, kernel 19, process 6, CI 5, deploy 5, cage 4). Map every non-doc, non-generated #1179 file (1,307) to exactly one slice ID below (REC-P0P1.1 to .18, REC-P2 to REC-P6b, REC-DOCS), a re-derive bucket, or drop. Import of #1179's findings ledger (158 original IDs plus a 328-ID overlay, kept under `target/recovery-*` on a task host and not committed) is parked (UR-PK-REC-LEDGER); list the known open P1s from `docs/architecture/recoverable-agent-runtime/implementation/STATUS.md` on #1179 instead.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `python3 -I scripts/rec-slice-manifest.py --check f217de1fb` reports every path assigned exactly once; its test covers an unassigned path and a double assignment.

## Log
- 2026-10-09T04:51:58Z connor: created
