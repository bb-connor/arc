---
id: "ECON-SALVAGE-958"
title: "Salvage #958 escrow accept() invariants"
severity: "P2"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["UR-LEDGER-CARRY"]
paths: ["crates/platform/chio-commerce-order/src/escrow.rs", "crates/platform/chio-commerce-order/tests/escrow_accept.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: section 7 (from #958: the escrow `accept()` invariants). Source: PR #958 (ref `origin/chio/m1-launch`) `crates/platform/chio-commerce-order/src/escrow.rs` `pub fn accept(` around line 714. Post-#1160 main has no escrow module in `chio-commerce-order` (it has `payment.rs`, `settlement.rs`, `mandate.rs`). Port `escrow.rs` as a self-contained module limited to the escrow state machine and its `accept()` invariants (drop the marketplace and Chio Pass wiring), or, if the owner of Lane SHARE judges escrow out of the preview scope (ADR-0035: no escrow claims), record the invariants as tests against `settlement.rs` and adjudicate the rows. Address the 57 ledger rows with `landing_pr` 958. Keep payment claims `detect_only`; no escrow claims in public copy (section 9).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `crates/platform/chio-commerce-order/tests/escrow_accept.rs` covers each ported invariant with a negative test.
- `cargo test -p chio-commerce-order` passes; #958 rows in PR-CARRY-FORWARD all dispositioned.

## Log
- 2026-10-09T04:51:58Z connor: created
