---
id: "KSPEC-04.P1.3"
title: "AdmittedWorkDrain on revocation, shared classifier with cause, ProcessLivenessGuard"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["KSPEC-04.P1.2"]
paths: ["crates/kernel/chio-kernel/src/kernel/admission_coordinator/drain.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/recovery/operation.rs", "crates/kernel/chio-process/src/liveness_guard.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 16.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-3 (KSPEC-04 phases 1 and 2: subtree closure with the dispatch-commit fence, then ProcessTree closure). Spec: `docs/superpowers/specs/2026-10-04-authority-space-teardown-design.md` (KSPEC-04). The drain classifier shares the per-item step with the startup sweep (one sweep owner, CT-SETTLE) and takes a cause parameter.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Kani: the classifier is total and never compensates after dispatch; the liveness guard denies a cancelled subtree.

## Log
- 2026-10-09T04:51:58Z connor: created
