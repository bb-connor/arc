---
id: "COOP-2.8"
title: "Safe HTTP methods deny by default for federated doors"
severity: "P1"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["COOP-2.4"]
paths: ["crates/protocol/chio-openapi/src/policy.rs", "crates/products/chio-api-protect/src/proxy/config.rs", "spec/OPENAPI-INTEGRATION.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-2 ("a production-grade pair"), G2 exit (revocation propagates live; rotation exercised; independent-operation record published). `DefaultPolicy::for_method` returns `SessionAllow` for safe methods (`chio-openapi/src/policy.rs:29`). Add `--federated-door`, which flips that to deny-by-default and refuses `--allow-anonymous-reads`.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-openapi federated_safe_methods_deny` passes; a GET without a capability on a federated door is denied with a receipt.

## Log
- 2026-10-09T04:51:58Z connor: created
