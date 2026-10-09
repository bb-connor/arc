---
id: "KSPEC-07.AMEND"
title: "Amend KSPEC-07 to add AgentHostBwrap and Seatbelt backend kinds"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["DOCS-1174.1", "KERN-REGROUND"]
paths: ["docs/superpowers/specs/2026-10-04-microkernel-isolation-backend-design.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 5.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-5 (KSPEC-07 steps 1 and 2, plus `AgentHostBwrap` and `Seatbelt` backend kinds, before any HOST-M2 isolation claim). Spec: `docs/superpowers/specs/2026-10-04-microkernel-isolation-backend-design.md` (KSPEC-07). No backend-kind enum exists in code: `ConfinementBackendKind {{ LinuxCage, FirecrackerGuest, ProcessContainer }}` exists only in the spec text (section 5.2). `AgentHostBwrap` and `Seatbelt` are #1177's proposed S7 amendment (Omarchy architecture review, ANNEX, NORTH-STAR-FLOWS). Add both kinds to the closed enum with surface and observer mapping rows; `Seatbelt` renders unconfined/unavailable until macOS HOST-M2 qualifies it (after the test).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Section 5.2 table has rows for both kinds; reviewed by Lane KERNEL; no em dashes.

## Log
- 2026-10-09T04:51:58Z connor: created
