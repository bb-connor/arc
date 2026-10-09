---
id: "COOP-1.6"
title: "Door receipts exportable and verified in the evidence package"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-WIRE.3"]
paths: ["crates/platform/chio-control-plane/src/evidence_export/verification.rs", "crates/platform/chio-control-plane/src/evidence_export/tests/door_receipts.rs", "crates/products/chio-cli/tests/evidence_export/door_receipts.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-1 ("HOST-M1, re-cut server-first"), G2 steps (passport, challenge, inbox, holder pickup, allow and deny at the door, offline verification against a pinned partner card). Plan source: #1177 `docs/superpowers/plans/2026-10-08-m1-cooperate-0.md` as re-cut by COOP-1.0. HOST-M1 never depends on #1179. Roadmap COOP-1 ("door receipts are exportable"; roadmap says `http_receipts` are missing). Precise gap on #1160: api protect stores each `HttpReceipt` as a projected `ChioReceipt` with metadata `chio_http_receipt_v1` in its own store (`crates/products/chio-api-protect/src/proxy/evidence.rs`; `chio-http-core/src/receipt.rs:316`); `http_receipts` is a legacy table. The door store is separate from trust-control's, one package covers one DB, the verifier never checks the embedded `HttpReceipt`, and no published key set names the door signer. Make `evidence verify` check every embedded `chio_http_receipt_v1` (signature, kernel key, equality with its projection), add an export-and-verify regression for door allow and deny receipts, and document the two-package shape.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-cli --test evidence_export door_receipts` passes: allow and deny from api protect exported with the door seed verify offline; a tampered embedded receipt fails.

## Log
- 2026-10-09T04:51:58Z connor: created
