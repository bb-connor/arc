---
id: "KSPEC-08.P1.9"
title: "Offline CLI stop and unreadable-journal bypass with Reconcile (S25, S25a)"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["KSPEC-08.P1.3", "KSPEC-08.P1.8"]
paths: ["crates/products/chio-cli/src/cli/stop/offline.rs", "crates/platform/chio-store-sqlite/src/serving_owner/stop_intent.rs", "crates/platform/chio-store-sqlite/src/admission_operation_store/stop_epoch.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-1 (KSPEC-08 phase 1: KDEF-D2, N22, N23; durable restart-safe stop with an allocated schema slot; reachable from the process-host socket and the CLI). Spec: `docs/superpowers/specs/2026-10-04-durable-stop-epoch-design.md` (rule numbers S1 to S38 below refer to it). An operator must be able to stop a host that is down: the offline CLI writes the stop intent so the next boot comes up `ready_stopped`.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Offline stop while the host is down, then boot, gives `ready_stopped`; the unreadable-journal bypass test passes in its pre-S28 (shared-credential) form.

## Log
- 2026-10-09T04:51:58Z connor: created
