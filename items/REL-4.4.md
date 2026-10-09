---
id: "REL-4.4"
title: "Dashboard authority-tree and pool views"
severity: "P1"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["REL-4.1"]
paths: ["crates/products/chio-cli/dashboard/src/components/AuthorityTree*.tsx", "crates/products/chio-cli/dashboard/src/components/PoolView*.tsx", "crates/platform/chio-control-plane/src/trust_control/authority_tree_handlers.rs", "crates/platform/chio-control-plane/src/trust_control/service_runtime/router/authority_tree.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: REL-4 ("authority-tree and pool views"). Read-only views of the delegation/authority tree (root grant, children, attenuation, revocation state) and of holds per family (ceiling, held, captured, released). Use existing kernel data now; SHARE-1 adds family caps later and the view must render them when present. The existing `DelegationChain.tsx` and `BudgetSparkline.tsx` are the starting components.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Handler test returns a tree for a fixture with three levels and a revoked branch; component tests render it.
- `npm test` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
