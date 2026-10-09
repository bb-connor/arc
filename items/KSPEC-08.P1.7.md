---
id: "KSPEC-08.P1.7"
title: "Mount the stop routes on trust-control, api protect and hosted MCP (KDEF-N22)"
severity: "P1"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-CTRL.3", "KSPEC-08.P1.2", "KSPEC-08.P1.4", "UR-U4", "COOP-1.1"]
paths: ["crates/platform/chio-control-plane/src/trust_control/service_runtime/router/stop.rs", "crates/platform/chio-control-plane/src/trust_control/stop_handlers.rs", "crates/products/chio-api-protect/src/proxy/router.rs", "crates/products/chio-api-protect/src/proxy/stop.rs", "crates/protocol/chio-mcp-remote/src/remote_mcp/admin.rs", "crates/protocol/chio-mcp-remote/src/remote_mcp/admin/stop.rs", "crates/platform/chio-http-core/src/emergency.rs", "crates/platform/chio-http-core/src/routes.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-1 (KSPEC-08 phase 1: KDEF-D2, N22, N23; durable restart-safe stop with an allocated schema slot; reachable from the process-host socket and the CLI). Spec: `docs/superpowers/specs/2026-10-04-durable-stop-epoch-design.md` (rule numbers S1 to S38 below refer to it). 
Today the route constants (`crates/platform/chio-http-core/src/routes.rs:33`) and `emergency_route_registrations()` (line 110) have no non-test caller; none of the three routers mounts them. Mount stop, restrict, relax, resume and status on each surface using the existing control credential with a constant-time compare, recording `SharedCredential` (S18, S30). Status answers even when the host is not ready. Retire `EmergencyAdmin`'s process-only path or make it delegate to the durable path. Use the trust-control `stop` router fragment created by COOP-1.1.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Route tests on all three surfaces for the three results, a wrong token, and status while not ready.
- `cargo test -p chio-control-plane stop_routes`, `cargo test -p chio-api-protect stop`, `cargo test -p chio-mcp-remote admin::stop` pass.

## Log
- 2026-10-09T04:51:58Z connor: created
