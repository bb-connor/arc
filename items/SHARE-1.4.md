---
id: "SHARE-1.4"
title: "Enforce (or explicitly declare) what basis-point shares bound"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["SHARE-1.1"]
paths: ["crates/core/chio-core-types/src/capability/attenuation.rs", "crates/core/chio-core-types/src/capability/validation.rs", "crates/core/chio-core-types/src/capability/bps_share_tests.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: SHARE-1 ("decide what basis-point shares actually bound; today they are declarations only"). Implement the decision recorded in `docs/architecture/CONSUMPTION-LEDGER.md` (SHARE-1.1): either basis-point shares become an enforced child ceiling computed against the parent's hold-ledger ceiling at delegation and at admission, or they are relabelled as declarations everywhere they surface (types, docs, receipts) with `boundary_class: advisory_only`. Either way, no surface may imply enforcement that does not exist.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `crates/core/chio-core-types/src/capability/bps_share_tests.rs` covers the chosen semantics (enforced: child over share denies; declared: receipts and docs carry the advisory label).
- `cargo test -p chio-core-types capability` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
