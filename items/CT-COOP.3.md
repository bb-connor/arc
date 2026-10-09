---
id: "CT-COOP.3"
title: "CT-COOP reference types and vector conformance"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-COOP.2"]
paths: ["crates/trust/chio-credentials/src/partner_card.rs", "crates/trust/chio-credentials/src/passport_status.rs", "crates/trust/chio-credentials/src/lib.rs", "crates/kernel/chio-kernel/src/dpop/http.rs", "crates/tooling/chio-spec-validate/tests/coop_contract.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.3 CT-COOP. Implement sign and verify for the partner card and its continuity, the status statement with freshness, the pickup proof, and an HTTP DPoP binding helper (`dpop/http.rs`, one `mod` line in `dpop.rs`). Fail closed everywhere. No routes (COOP-1 and COOP-2 add them).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-spec-validate --test coop_contract`, `cargo test -p chio-credentials partner_card passport_status` and `cargo test -p chio-kernel dpop::http` pass against every CT-COOP vector.

## Log
- 2026-10-09T04:51:58Z connor: created
