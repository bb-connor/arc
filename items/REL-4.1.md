---
id: "REL-4.1"
title: "Trust-control dashboard authentication beyond `?token=`"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-CTRL.2", "COOP-1.1"]
paths: ["crates/platform/chio-control-plane/src/trust_control/service_runtime/router/dashboard.rs", "crates/platform/chio-control-plane/src/trust_control/service_runtime/dashboard_auth.rs", "crates/products/chio-cli/dashboard/src/api.ts", "crates/products/chio-cli/dashboard/src/api.test.ts"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: REL-4 ("the trust-control dashboard is the one operator web client. It is read-only today and served only from a relative path"; it gains "authentication beyond `?token=`"), CT-CTRL (per-route principals in place of one shared service token). The SPA is served from `dashboard/dist` (`crates/platform/chio-control-plane/src/trust_control/service_types/paths.rs:250` `DASHBOARD_DIST_DIR`; `crates/platform/chio-control-plane/src/trust_control/service_runtime/router.rs:646-670`). Replace query-string token auth with a login flow that yields a short-lived, HttpOnly, SameSite=Strict session bound to a CT-CTRL principal (operator, approver, viewer), plus CSRF protection for the mutating routes REL-4.2 adds. Tokens never appear in URLs or logs. Boundary: `prevent` for operator actions.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Rust tests in `dashboard_auth.rs`: no session denies, expired session denies, viewer cannot call an approver route, token in query string is rejected.
- `npm test` in `crates/products/chio-cli/dashboard` passes with the new api client tests.

## Log
- 2026-10-09T04:51:58Z connor: created
