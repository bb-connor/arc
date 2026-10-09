---
id: "COOP-2.6a"
title: "DPoP verification for federated grants at the HTTP door (D6)"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-COOP.3"]
paths: ["crates/platform/chio-http-core/src/authority.rs", "crates/products/chio-api-protect/src/proxy/http.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-2 ("a production-grade pair"), G2 exit (revocation propagates live; rotation exercised; independent-operation record published). Roadmap gap: "At proxied routes a federated capability is a bearer token, because holder possession is not checked". `validate_presented_capability` (`chio-http-core/src/authority.rs:1131`) rejects DPoP-required grants and projects with `dpop_proof: None` (line 1012). Verify HTTP-bound proofs (CT-COOP.2 profile) with `verify_dpop_proof` and the durable replay store (`chio-store-sqlite/src/admission_operation_store/dpop_replay.rs`) before projection; keep refusing proofs that are not HTTP-bound. D6 recommendation (parked UR-D6). Boundary: `prevent`.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-api-protect inbound_authority` passes: `bearer_federated_cap_denied_without_proof`, `replayed_proof_denied`, `proof_for_other_route_denied`.

## Log
- 2026-10-09T04:51:58Z connor: created
