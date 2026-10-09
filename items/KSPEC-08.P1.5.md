---
id: "KSPEC-08.P1.5"
title: "Tier-1 stop at every mint path and AllowIfContainment for governed active response (S8)"
severity: "P1"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["KSPEC-08.P1.4"]
paths: ["crates/kernel/chio-kernel/src/kernel/validation/issuance.rs", "crates/products/chio-api-protect/src/proxy/sidecar.rs", "crates/platform/chio-control-plane/src/trust_control/passport_handlers.rs", "crates/kernel/chio-kernel/src/kernel/active_response_executor.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-1 (KSPEC-08 phase 1: KDEF-D2, N22, N23; durable restart-safe stop with an allocated schema slot; reachable from the process-host socket and the CLI). Spec: `docs/superpowers/specs/2026-10-04-durable-stop-epoch-design.md` (rule numbers S1 to S38 below refer to it). 
Closes KDEF-D2's "unchecked by issuance": `issue_capability`, the sidecar mint and passport issuance deny while stopped; governed active response honours `allow_containment` and the host latch. Passport issuance on a host without the store is listed as `unchecked` in status output. `passport_handlers.rs` is also leased by COOP-1 items; this item only adds the stop check (one call) and must not reorder the handler.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Tests: `issue_capability_denies_while_stopped`, `sidecar_mint_denies_while_stopped`, `active_response_honours_allow_containment`; `cargo test -p chio-kernel stopped` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
