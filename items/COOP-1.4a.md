---
id: "COOP-1.4a"
title: "Inbox routes and holder pickup authenticated by the subject key"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["COOP-1.1", "COOP-1.2", "COOP-1.3", "CT-CTRL.2"]
paths: ["crates/platform/chio-control-plane/src/trust_control/issuance_request_handlers.rs", "crates/platform/chio-control-plane/src/trust_control/service_types/paths.rs", "crates/platform/chio-control-plane/src/trust_control/service_types/requests.rs", "crates/platform/chio-control-plane/src/trust_control/service_runtime/router/federation.rs", "crates/platform/chio-control-plane/src/trust_control/service_runtime/client/operations.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-1 ("HOST-M1, re-cut server-first"), G2 steps (passport, challenge, inbox, holder pickup, allow and deny at the door, offline verification against a pinned partner card). Plan source: #1177 `docs/superpowers/plans/2026-10-08-m1-cooperate-0.md` as re-cut by COOP-1.0. HOST-M1 never depends on #1179. The roadmap notes the inbox design has no way to return the capability to the holder. Public submit verifies the presentation without consuming the challenge; admin list, approve, deny (plan Task 5); approve consumes the challenge and stores the capability; `POST /v1/public/federation/issuance-requests/{challenge_id}/pickup` verifies the CT-COOP.2 pickup proof against the record's subject (wrong key, replayed nonce or stale timestamp refused) and returns the capability once. A clock error returns 503. Principals per CT-CTRL.2 (`Public`, `Holder`, `Admin`). Boundary: `prevent`.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-cli --test issuance_inbox` passes: `inbox_submit_list_approve_and_refuse_duplicates`, `rejected_presentation_never_reaches_inbox`, `deny_consumes_the_challenge`, `pickup_requires_subject_key`, `pickup_replay_refused`, `pickup_before_approval_is_pending`.

## Log
- 2026-10-09T04:51:58Z connor: created
