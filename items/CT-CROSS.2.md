---
id: "CT-CROSS.2"
title: "Cross-org envelope reference types and verifier"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-CROSS.1", "CT-COOP.3"]
paths: ["crates/trust/chio-federation/src/cross_org.rs", "crates/trust/chio-federation/tests/cross_org_vectors.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: CT-CROSS. Envelope sign and verify, bounded replay window, SPKI pin check helpers, key resolution through the partner card. Add one `mod` line to `crates/trust/chio-federation/src/lib.rs` (WORK-SLICE-G.1 also edits this crate; land this first or rebase).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-federation --test cross_org_vectors` passes against every CT-CROSS vector.

## Log
- 2026-10-09T04:51:58Z connor: created
