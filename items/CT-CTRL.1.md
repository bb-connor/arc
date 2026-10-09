---
id: "CT-CTRL.1"
title: "OpenAPI for trust-control (HOST-M1 subset) and the api protect sidecar, with route drift tests"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-COOP.2"]
paths: ["spec/openapi/trust-control.v0.yaml", "spec/openapi/api-protect-sidecar.v0.yaml", "crates/platform/chio-control-plane/tests/openapi_route_drift.rs", "crates/products/chio-api-protect/tests/openapi_route_drift.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.3 CT-CTRL ("OpenAPI for trust-control and the `chio api protect` sidecar"); KERN unowned primitive "a versioned control API" (this contract owns it). No OpenAPI document exists for either today (`spec/OPENAPI-INTEGRATION.md` covers ingesting upstream APIs; `spec/schemas/chio-wire/v1/trust-control/` covers only lease, heartbeat and attestation). Trust-control has 209 `*_PATH` constants (`crates/platform/chio-control-plane/src/trust_control/service_types/paths.rs`) and 151 `validate_service_auth` uses. Specify passport, challenge, federation issue and status; inbox submit, list, approve, deny and pickup; authority status and the partner card; revocations including a door-scoped delta; each with an `x-chio-principal` annotation (CT-CTRL.2 defines the classes). Drift tests parse the path constants and fail on any route neither specified nor on an explicit `unspecified` allowlist (expected to shrink).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-control-plane --test openapi_route_drift` and `cargo test -p chio-api-protect --test openapi_route_drift` pass; the OpenAPI files validate with a standard OpenAPI 3.1 linter (command in the PR).

## Log
- 2026-10-09T04:51:58Z connor: created
