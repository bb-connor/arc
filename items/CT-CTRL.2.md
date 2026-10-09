---
id: "CT-CTRL.2"
title: "Per-route principal model replacing the shared service token"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-CTRL.1"]
paths: ["spec/CHIO_CONTROL_PRINCIPALS.md", "crates/platform/chio-control-plane/src/trust_control/route_principals.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.3 CT-CTRL ("per-route principals in place of one shared service token"). Today trust-control uses one `service_token` plus separate validators (`validate_cluster_peer_auth`, `validate_authority_workload_auth`, `validate_authority_issue_auth`, `report_validation.rs:224-459`), and api protect uses one `sidecar_control_token` (`docs/security/sidecar-control-authority.md`). Define `RoutePrincipalClass`: `Public`, `Holder` (subject-key signed), `PartnerSigned`, `DoorWorkload` (new: revocation feed, key history), `AuthorityWorkload`, `TenantRead`, `ClusterPeer`, `Admin`, `OperatorRoster` (labelled `SharedCredential` until KSPEC-08 S28). Classify every route; no behaviour change in this item.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-control-plane route_principals::every_path_has_one_principal` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
