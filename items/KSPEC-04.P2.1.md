---
id: "KSPEC-04.P2.1"
title: "ProcessTree closure"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["KSPEC-04.P1.4", "CT-ABI.3"]
paths: ["crates/kernel/chio-process/src/lib.rs", "crates/kernel/chio-process/src/store.rs", "crates/kernel/chio-process/src/security.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-3 (KSPEC-04 phases 1 and 2: subtree closure with the dispatch-commit fence, then ProcessTree closure). Spec: `docs/superpowers/specs/2026-10-04-authority-space-teardown-design.md` (KSPEC-04). Phase 2: closing a ProcessTree closes every capability subtree it owns; ABI v4 (CT-ABI) carries the closure state.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- "Subtree closure noninterference" (processes R, A, B, A1) passes: closing A leaves B and R untouched; `cargo test -p chio-process closure` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
