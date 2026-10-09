---
id: "REC-P0P1.1"
title: "Core and security-type recovery contracts"
severity: "P2"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["REC-1172", "REC-P0P1.0", "CT-SETTLE.1"]
paths: ["crates/core/chio-core-types/src/recovery/**", "crates/core/chio-core-types/tests/recovery_*.rs", "crates/security/chio-security-types/src/recovery/**", "crates/security/chio-security-types/src/semantic/**", "crates/security/chio-security-types/src/knowledge/**", "crates/security/chio-security-types/tests/bounded_sequence_decode.rs", "crates/security/chio-security-types/tests/recovery_bounds.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method (applies to every REC-P0P1 slice): do not run `git rebase`. Re-land from the frozen #1179 source `f217de1fb` (PR head; the roadmap pin 491bd01b5 is stale) onto `integration/beta-next` by path: `git checkout f217de1fb -- <slice globs>`, then repair against #1160's code, and record the slice's source-manifest digest in `docs/architecture/recoverable-agent-runtime/implementation/REBASE-MANIFEST.json` (created by REC-P0P1.0). Keep each slice compiling: new kernel trait methods land with fail-closed default bodies (#1160 precedent `store.rs:874`); `recovery_authority()` returns `None` until the store slices land. Never hand-merge `_generated` files (REC-P0P1.17 regenerates). Roadmap Lane REC requirements this lane must meet: rebase onto #1160's paged sweep rather than porting the old loop; adopt CT-SETTLE and the KSPEC-08 stop chain (KDEF-N24); adopt process ABI v4 (KDEF-N13) and the cage port (KDEF-N16); fix KDEF-N15 (wall-clock time in authority evidence); fix every open P1; take schema slots through the ledger lock; regenerate the SDKs. The #1179 rebase is one of the two riskiest pieces in the roadmap and gets the earliest prototype. REC-P0 (contracts: closed schemas, pure dependency graph, effect/release/control vocabulary, bounded intake 64 KiB and depth 16; #1172 `10-delivery-decisions.md:7-15`). Port the P0 and P1 vocabulary plus the bounded-sequence decoder fix; port the port definitions that #1179 kept in `ports_parts/part_01.rs` (deleted on #1160) into #1160's current port module.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-core-types --test recovery_contracts --test recovery_authority_contracts` and `cargo test -p chio-security-types` pass; the `no_std` check #1179 used passes.

## Log
- 2026-10-09T04:51:58Z connor: created
