---
id: "REC-EXIT"
title: "Qualified recovery of a lost reply by original identity (no second dispatch)"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["REC-P0P1.Q", "REC-P0P1.8"]
paths: ["crates/platform/chio-control-plane/tests/recovery_lost_reply_original_identity.rs", "docs/architecture/recoverable-agent-runtime/implementation/qualification/rec-exit-*.json"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: Lane REC exit ("qualified recovery of a lost reply by original identity. This unblocks WORK-W1.5b, W1.6b and W2.4"); success-test criterion (c); G4/G5 claim `prevent`, `blocked_by_adr` until CT-SETTLE and D2 are decided. Drop the reply after dispatch commit, kill the process and restart; the client recovers by original operation ID: exactly one provider effect, the original receipt, no second dispatch. Run in hosted CI and on two hosts as the dry run for the G4 lost-reply drill.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- The new test passes in hosted CI alongside `strict_nonce_unknown_effect_keeps_original_custody_after_process_death`; the qualification record names the run and hosts.

## Log
- 2026-10-09T04:51:58Z connor: created
