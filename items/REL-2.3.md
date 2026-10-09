---
id: "REL-2.3"
title: "`serve-http` accepts presented federated capabilities (holder-bound)"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["REL-2.2", "CT-COOP.3", "CT-CTRL.1"]
paths: ["crates/protocol/chio-mcp-remote/src/remote_mcp/http_service_auth.rs", "crates/protocol/chio-mcp-remote/src/remote_mcp/sender_constraint.rs", "crates/protocol/chio-mcp-remote/src/remote_mcp/hosted_tests/presented_capability.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: REL-2 ("`chio mcp serve-http` accepts presented, federated capabilities, or a bridge-daemon shim adds them"). Today only `chio api protect` admits a presented capability (`X-Chio-Capability`, `crates/products/chio-api-protect/src/evaluator.rs:476`, `proxy/http.rs:112`) against a pinned `CHIO_TRUSTED_ISSUER_KEY`; serve-http authenticates with OAuth/JWT (`crates/protocol/chio-mcp-remote/src/remote_mcp/oauth/*`). Add presented-capability admission to serve-http using the same verification path as api protect, with holder possession checked per CT-COOP's DPoP profile (D6 recommendation; `crates/protocol/chio-mcp-remote/src/remote_mcp/sender_constraint.rs` already carries sender-constraint plumbing) so a federated capability is never a bearer token. Prefer this in-process route over a bridge-daemon shim; record the choice. Boundary: `prevent`, G2 claim "B's door admits A's agent only within B-issued, attenuated, holder-bound authority".

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `crates/protocol/chio-mcp-remote/src/remote_mcp/hosted_tests/presented_capability.rs`: valid holder-bound capability admitted; missing proof denied; proof from a different key denied; untrusted issuer denied; each with a receipt.
- `cargo test -p chio-mcp-remote presented_capability` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
