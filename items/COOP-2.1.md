---
id: "COOP-2.1"
title: "`chio partner add|list|show|remove` over the partner card"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["COOP-1.11"]
paths: ["crates/products/chio-cli/src/cli/dispatch/partner.rs", "crates/platform/chio-control-plane/src/partner_registry.rs", "crates/products/chio-cli/tests/partner_registry.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-2 ("a production-grade pair"), G2 exit (revocation propagates live; rotation exercised; independent-operation record published). Verify the card and its continuity, then pin it. The registry feeds the verifier issuer allowlist, the evidence trust anchor, the status pull, the door's key set and CT-CROSS keys.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-cli --test partner_registry` passes, rejecting rollback and unsigned updates.

## Log
- 2026-10-09T04:51:58Z connor: created
