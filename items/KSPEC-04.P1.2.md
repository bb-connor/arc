---
id: "KSPEC-04.P1.2"
title: "Insertion, dispatch-commit and release fences"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["KSPEC-04.P1.1", "KSPEC-08.P1.6"]
paths: ["crates/kernel/chio-kernel/src/kernel/admission_coordinator.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_output.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-3 (KSPEC-04 phases 1 and 2: subtree closure with the dispatch-commit fence, then ProcessTree closure). Spec: `docs/superpowers/specs/2026-10-04-authority-space-teardown-design.md` (KSPEC-04). Must follow KSPEC-08.P1.6, which edits the same dispatch CAS.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- "Insertion fence" pause test passes; Loom: fence against the `DispatchCommitted` CAS.

## Log
- 2026-10-09T04:51:58Z connor: created
