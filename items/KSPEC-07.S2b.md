---
id: "KSPEC-07.S2b"
title: "worker_profile attribution for direct and container launches"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["KSPEC-07.S2a", "KSPEC-04.P2.1"]
paths: ["crates/kernel/chio-process/src/attribution.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-5 (KSPEC-07 steps 1 and 2, plus `AgentHostBwrap` and `Seatbelt` backend kinds, before any HOST-M2 isolation claim). Spec: `docs/superpowers/specs/2026-10-04-microkernel-isolation-backend-design.md` (KSPEC-07). Attribution lives at `crates/kernel/chio-process/src/lib.rs:458-479` today; move it into `attribution.rs` (one re-export line in `lib.rs`, which KSPEC-04.P2.1 leases first) and add `worker_profile`.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- A profile mismatch denies even on an ordinary call; an absent profile renders as `direct` and never satisfies a required lane.

## Log
- 2026-10-09T04:51:58Z connor: created
