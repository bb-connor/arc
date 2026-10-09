---
id: "COOP-1.5"
title: "B's authority owns the delegation ceiling"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["COOP-1.4b", "CT-COOP.1"]
paths: ["crates/platform/chio-control-plane/src/trust_control/partner_ceilings.rs", "crates/platform/chio-control-plane/src/trust_control/passport_handlers.rs", "crates/platform/chio-control-plane/src/trust_control/service_types/requests.rs", "crates/products/chio-cli/src/cli/types/trust.rs", "crates/products/chio-cli/tests/federated_issue.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-1 ("HOST-M1, re-cut server-first"), G2 steps (passport, challenge, inbox, holder pickup, allow and deny at the door, offline verification against a pinned partner card). Plan source: #1177 `docs/superpowers/plans/2026-10-08-m1-cooperate-0.md` as re-cut by COOP-1.0. HOST-M1 never depends on #1179. Roadmap COOP-1 ("B's authority owns the delegation ceiling"). Today `FederatedDelegationPolicyDocument` is optional per request (`service_types/requests.rs:230-330`) and `body.partner` is never compared with the presenting passport's issuer. Add a per-partner ceiling registry at B, signed by B's authority and keyed by partner DID; mandatory for inbox approvals and for any presenter whose issuer is a registered partner; `body.partner` must equal the passport issuer; a request-supplied ceiling may only narrow the stored one. Boundary: `prevent` (G2 claim: within B-issued, attenuated authority).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `federated_issue_requires_partner_ceiling`, `federated_issue_rejects_partner_mismatch`, `federated_issue_request_ceiling_only_narrows` pass.

## Log
- 2026-10-09T04:51:58Z connor: created
