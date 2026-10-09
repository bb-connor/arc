---
id: "COOP-1.11"
title: "Partner card publication (`chio partner card export`, public route)"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-COOP.3", "COOP-1.4a", "COOP-1.8a"]
paths: ["crates/products/chio-cli/src/cli/types/partner.rs", "crates/products/chio-cli/src/cli/dispatch/partner.rs", "crates/platform/chio-control-plane/src/trust_control/partner_card_handlers.rs", "crates/products/chio-cli/tests/partner_card.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-1 ("HOST-M1, re-cut server-first"), G2 steps (passport, challenge, inbox, holder pickup, allow and deny at the door, offline verification against a pinned partner card). Plan source: #1177 `docs/superpowers/plans/2026-10-08-m1-cooperate-0.md` as re-cut by COOP-1.0. HOST-M1 never depends on #1179. `GET /v1/public/partner-card` built from authority status, configured door signer keys and advertised URLs, signed with the org key through custody. Add the path in the `federation` router fragment (after COOP-1.4a, which also edits it) and specify it in CT-CTRL's OpenAPI.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-cli --test partner_card` passes: `card_round_trips_and_verifies`, `card_rotation_keeps_continuity`.

## Log
- 2026-10-09T04:51:58Z connor: created
