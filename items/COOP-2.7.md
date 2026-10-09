---
id: "COOP-2.7"
title: "Authority key history at the door: rotation is not an outage"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["COOP-2.4", "COOP-2.1", "COOP-2.6a"]
paths: ["crates/products/chio-cli/src/cli/runtime.rs", "crates/products/chio-api-protect/src/proxy/authority_keys.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-2 ("a production-grade pair"), G2 exit (revocation propagates live; rotation exercised; independent-operation record published). Today the door reads `CHIO_TRUSTED_ISSUER_KEY`/`KEYS` once at startup (`parse_trusted_capability_issuers_from_env`, `chio-cli/src/cli/runtime.rs:687`; `trusted_capability_issuers` at 665), so rotating B's key needs a door restart. Pull B's key set with validity windows (partner card format) under the `DoorWorkload` principal. Small edits in `proxy/state.rs` follow COOP-2.4.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `rotation_mid_run_keeps_door_serving` passes: keys rotate mid-run, old-key receipts still verify within their window, new-key capabilities are admitted without restart.

## Log
- 2026-10-09T04:51:58Z connor: created
