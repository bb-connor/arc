---
id: "REC-P0P1.4"
title: "rusqlite and cpp-demangle forks: keep (with audits) or drop"
severity: "P2"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["REC-P0P1.0"]
paths: ["third_party/rusqlite-chio/**", "third_party/cpp-demangle-chio/**", "supply-chain/**", "crates/platform/chio-sqlite-file-identity/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method (applies to every REC-P0P1 slice): do not run `git rebase`. Re-land from the frozen #1179 source `f217de1fb` (PR head; the roadmap pin 491bd01b5 is stale) onto `integration/beta-next` by path: `git checkout f217de1fb -- <slice globs>`, then repair against #1160's code, and record the slice's source-manifest digest in `docs/architecture/recoverable-agent-runtime/implementation/REBASE-MANIFEST.json` (created by REC-P0P1.0). Keep each slice compiling: new kernel trait methods land with fail-closed default bodies (#1160 precedent `store.rs:874`); `recovery_authority()` returns `None` until the store slices land. Never hand-merge `_generated` files (REC-P0P1.17 regenerates). Roadmap Lane REC requirements this lane must meet: rebase onto #1160's paged sweep rather than porting the old loop; adopt CT-SETTLE and the KSPEC-08 stop chain (KDEF-N24); adopt process ABI v4 (KDEF-N13) and the cage port (KDEF-N16); fix KDEF-N15 (wall-clock time in authority evidence); fix every open P1; take schema slots through the ledger lock; regenerate the SDKs. The #1179 rebase is one of the two riskiest pieces in the roadmap and gets the earliest prototype. #1179 patches rusqlite to `third_party/rusqlite-chio` and adds `third_party/cpp-demangle-chio` via `[patch.crates-io]` (its `Cargo.toml:255-258`). Decide whether the callback-ownership repair is still required on #1160's rusqlite 0.39. If kept, add cargo-vet audits and the upstream PR reference; the root `[patch]` edit is a small coordinated change to `Cargo.toml`.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo vet` and `cargo deny check` pass; the fork's own tests (`third_party/rusqlite-chio/tests/*`) pass, or the fork is dropped with a test proving #1160's rusqlite behaves correctly.

## Log
- 2026-10-09T04:51:58Z connor: created
