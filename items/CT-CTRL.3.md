---
id: "CT-CTRL.3"
title: "Freeze the KSPEC-08 stop wire contract and stop routes (part of CT-CTRL)"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-CTRL.1", "CT-WIRE.1", "DOCS-1174.1"]
paths: ["crates/core/chio-core-types/src/stop.rs", "crates/core/chio-core-types/src/lib.rs", "spec/schemas/chio-wire/v1/security/stop-epoch-v1.schema.json", "spec/schemas/chio-wire/v1/security/stop-control-v1.schema.json", "tests/bindings/vectors/security/stop/**", "spec/openapi/stop.v0.yaml"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.3 CT-CTRL ("the KSPEC-08 stop routes"), KERN-1. Spec: `docs/superpowers/specs/2026-10-04-durable-stop-epoch-design.md` (KSPEC-08). Freeze the closed types `StopScope` (Kernel, Tenant, Recovery), `StopTransition` (7 variants), `StopEpochV1`, `StopEpochId`, `StopAuthorizer::SharedCredential { credential_id_hash }`, `DecisionTime`, `StopObservation`, and the route and socket DTOs (stop, restrict, relax, resume, status) with results `stop_durable`, `stop_not_durable`, `stop_outcome_unknown`, readiness `ready_stopped`, and `host_latch`. Phase 1 uses only Kernel scope but the enums are closed now so phases 4 and 5 need no wire break. Add the stop section to the CT-CTRL OpenAPI (`spec/openapi/stop.v0.yaml`, referenced from CT-CTRL.1's documents) with the `OperatorRoster` principal labelled `SharedCredential` until KSPEC-08 S28. Decision gate: KSPEC-08 open decision 2 (containment allowed by default) is recorded as the spec's recommendation (parked UR-PK-KSPEC08-DEC); note it in the contract header.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-core-types stop`; codegen no-diff (`cargo xtask codegen --lang rust --check`); `python3 scripts/check-wire-schemas.py` passes with the new identifiers.
- Negative vectors reject unknown fields and unknown enum variants.

## Log
- 2026-10-09T04:51:58Z connor: created
