---
id: "COOP-2.5"
title: "Durable revocation oracle (generalize the custody leaf-replay design)"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["COOP-2.3"]
paths: ["crates/trust/chio-revocation-oracle/src/durable.rs", "crates/trust/chio-revocation-oracle/Cargo.toml", "crates/trust/chio-custody-hw/src/revocation.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-2 ("a production-grade pair"), G2 exit (revocation propagates live; rotation exercised; independent-operation record published). Roadmap COOP-2 ("a durable revocation oracle (today only `InMemoryRevocationOracle` exists)"); KERN unowned primitive "the durable revocation oracle and the portable verifier's lifecycle check" (this item plus COOP-2.2 own them; accountable owner parked as UR-PK-KDEF-OWNERS). Correction: `crates/trust/chio-custody-hw/src/revocation.rs` already has a durable `SqliteCredentialRevocationOracle` (feature `sqlite-store`) that replays persisted leaves into the in-memory oracle; generalize it into `chio-revocation-oracle` behind a `sqlite` feature, feed it from trust-control passport revocations through `passport_bridge`, and publish signed epoch roots (`SignedEpochRoot`, `verify_fresh_epoch_root` with `FreshnessConfig::fail_closed`).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-revocation-oracle --features sqlite durable` passes including `root_identical_after_restart`.

## Log
- 2026-10-09T04:51:58Z connor: created
