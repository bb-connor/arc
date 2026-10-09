---
id: "COOP-1.1"
title: "Trust-control router fragments for every planned route family (collision fix)"
severity: "P1"
wave: 1
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["crates/platform/chio-control-plane/src/trust_control/service_runtime/router.rs", "crates/platform/chio-control-plane/src/trust_control/service_runtime/router/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 5.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.2 spirit (prevent lane collisions). `crates/platform/chio-control-plane/src/trust_control/service_runtime/router.rs` is the one file every new trust-control route touches (inbox, partner card, door revocation feed, dashboard auth, approvals, authority tree, stop, closure, work). Mechanically move the federation and passport routes into a `router/federation.rs` fragment, and create empty, mounted fragments `router/{door,dashboard,approvals,authority_tree,stop,closure,work}.rs` so later items only touch their own fragment. No route changes.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-cli --test federated_issue` passes with the same test count; route table snapshot (all `*_PATH` constants mounted) is unchanged.

## Log
- 2026-10-09T04:51:58Z connor: created
