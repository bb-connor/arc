---
id: "COOP-2.2"
title: "Issuer-signed lifecycle status pulled with a TTL, failing closed when stale"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["COOP-2.1", "COOP-1.5"]
paths: ["crates/platform/chio-control-plane/src/trust_control/config_and_public.rs", "crates/platform/chio-control-plane/src/trust_control/passport_handlers.rs", "crates/platform/chio-control-plane/src/trust_control/partner_status_pull.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-2 ("a production-grade pair"), G2 exit (revocation propagates live; rotation exercised; independent-operation record published). Roadmap gap: "A's passport revocation never reaches B. Federated issue reads B's own local status" (`resolve_passport_lifecycle_for_service`, `config_and_public.rs:679`). On A's side, `passport status publish` and the public resolve route serve signed statements (CT-COOP.2). B pulls from the card's URL into a TTL cache; stale cache or unreachable A yields pending or refused, never allow. Boundary: `prevent`.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `federated_issue_refuses_stale_partner_status` and `federated_issue_honors_partner_revocation` pass.

## Log
- 2026-10-09T04:51:58Z connor: created
