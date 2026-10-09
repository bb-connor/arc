---
id: "KERN-3.D5"
title: "Consult the issuance freeze with Delegate on every delegate mint path (KDEF-D5)"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["KERN-REGROUND", "KSPEC-08.P1.5"]
paths: ["crates/kernel/chio-kernel/src/kernel/validation/lineage.rs", "crates/kernel/chio-kernel/src/kernel/validation/issuance.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-3 (KDEF-D5). The freeze anchor is `crates/platform/chio-store-sqlite/src/security_state/issuance_freeze.rs:1246`; the only production queries construct `Issue` (`kernel/validation/issuance.rs:76,123`). Census every delegate mint path and consult the freeze with `Delegate`; extend `paths` at claim time to each path the census finds.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- A frozen lineage refuses `register_delegation_parent`; `cargo test -p chio-kernel issuance_freeze_delegate` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
