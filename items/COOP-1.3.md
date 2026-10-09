---
id: "COOP-1.3"
title: "Issuance inbox store with holder-pickup state"
severity: "P1"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-COOP.2"]
paths: ["crates/platform/chio-control-plane/src/issuance_requests.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-1 ("HOST-M1, re-cut server-first"), G2 steps (passport, challenge, inbox, holder pickup, allow and deny at the door, offline verification against a pinned partner card). Plan source: #1177 `docs/superpowers/plans/2026-10-08-m1-cooperate-0.md` as re-cut by COOP-1.0. HOST-M1 never depends on #1179. Plan Task 4 extended with `capability_json`, `passport_id`, `issued_at`, `picked_up_at`, a pickup-nonce table, and a TTL for issued-but-uncollected capabilities. Bounded at 256 pending; duplicate submission returns 409. All times are passed in (no wall-clock read in the store). One `mod` line in `lib.rs`.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-control-plane --lib issuance_requests` passes including `duplicate_submission_is_refused`, `decide_only_moves_pending_requests`, `list_filters_by_status`, `pickup_is_single_use`, `uncollected_capability_expires`.

## Log
- 2026-10-09T04:51:58Z connor: created
