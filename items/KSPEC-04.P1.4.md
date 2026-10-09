---
id: "KSPEC-04.P1.4"
title: "CapabilitySubtree closure record, bounded pages, signed artifact, admin routes, Apalache model"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["KSPEC-04.P1.3", "CT-CTRL.1", "COOP-1.1"]
paths: ["crates/kernel/chio-kernel/src/closure/**", "crates/platform/chio-control-plane/src/trust_control/closure_handlers.rs", "crates/platform/chio-control-plane/src/trust_control/service_runtime/router/closure.rs", "spec/schemas/chio-wire/v1/security/authority-space-closure-v1.schema.json", "formal/apalache/AuthoritySpaceClosure.tla"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 16.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-3 (KSPEC-04 phases 1 and 2: subtree closure with the dispatch-commit fence, then ProcessTree closure). Spec: `docs/superpowers/specs/2026-10-04-authority-space-teardown-design.md` (KSPEC-04). Closure routes go in the trust-control `closure` router fragment (COOP-1.1) and are specified in CT-CTRL's OpenAPI.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Apalache invariants pass and their four mutants fail; bounded-evidence page tests pass.

## Log
- 2026-10-09T04:51:58Z connor: created
