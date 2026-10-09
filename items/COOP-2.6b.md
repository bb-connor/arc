---
id: "COOP-2.6b"
title: "Federated issue sets dpop_required; holder proof helper in the CLI"
severity: "P1"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["COOP-2.6a", "COOP-2.2"]
paths: ["crates/platform/chio-control-plane/src/trust_control/passport_handlers.rs", "crates/products/chio-cli/src/cli/dispatch/did_passport.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-2 ("a production-grade pair"), G2 exit (revocation propagates live; rotation exercised; independent-operation record published). Federated issue never sets `dpop_required` today. Set it for federated grants and add a CLI helper that signs the HTTP proof with the holder key.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- The door step of `cooperate_two_domain` runs with a proof and fails without one.

## Log
- 2026-10-09T04:51:58Z connor: created
