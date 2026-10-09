---
id: "COOP-1.10"
title: "Two-domain HOST-M1 end-to-end test"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["COOP-1.4b", "COOP-1.5", "COOP-1.7", "COOP-1.11"]
paths: ["crates/products/chio-cli/tests/cooperate_two_domain.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-1 ("HOST-M1, re-cut server-first"), G2 steps (passport, challenge, inbox, holder pickup, allow and deny at the door, offline verification against a pinned partner card). Plan source: #1177 `docs/superpowers/plans/2026-10-08-m1-cooperate-0.md` as re-cut by COOP-1.0. HOST-M1 never depends on #1179. Passport, challenge, inbox submit, approval within B's ceiling, holder pickup, door allow and deny (deny receipt), export of the door store, verify with `--trust-anchor` B's card; all with #1160 flags.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-cli --test cooperate_two_domain` passes: `two_domains_cooperate_through_reviewed_issuance_and_offline_evidence`, `b_door_admits_in_scope_and_denies_out_of_scope_with_receipts`.

## Log
- 2026-10-09T04:51:58Z connor: created
