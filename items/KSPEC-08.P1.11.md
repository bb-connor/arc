---
id: "KSPEC-08.P1.11"
title: "KERN-1 hosted evidence and conformance (EV11)"
severity: "P1"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["KSPEC-08.P1.5", "KSPEC-08.P1.6", "KSPEC-08.P1.9", "KSPEC-08.P1.10", "KDEF-GT1"]
paths: ["crates/tooling/chio-conformance/tests/emergency_stop.rs", ".github/workflows/kernel-stop-evidence.yml", "docs/security/emergency-stop-scope.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-1 (KSPEC-08 phase 1: KDEF-D2, N22, N23; durable restart-safe stop with an allocated schema slot; reachable from the process-host socket and the CLI). Spec: `docs/superpowers/specs/2026-10-04-durable-stop-epoch-design.md` (rule numbers S1 to S38 below refer to it). Implement the KSPEC-08 section 16 phase 1 hosted scenarios and update the claim-limit text in the AC6 document from UR-U4. The EV11 ledger evidence is recorded by the ledger owner (do not lease the ledger).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- One hosted run passes: stop via route, restart into `ready_stopped`, deny, revoke and cancel still work, resume releases the withheld output; run URL recorded.

## Log
- 2026-10-09T04:51:58Z connor: created
