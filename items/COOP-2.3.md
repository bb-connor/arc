---
id: "COOP-2.3"
title: "Passport revocation cascades to B-issued capabilities"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["COOP-2.2"]
paths: ["crates/platform/chio-control-plane/src/trust_control/partner_status_pull.rs", "crates/platform/chio-control-plane/src/issuance_requests.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-2 ("a production-grade pair"), G2 exit (revocation propagates live; rotation exercised; independent-operation record published). When A revokes a passport, B revokes every capability it issued against it (feeds the door's revocation feed, COOP-2.4).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cooperate_two_domain::a_revocation_reaches_b_door` passes (extend COOP-1.10's test file with a small additive case).

## Log
- 2026-10-09T04:51:58Z connor: created
