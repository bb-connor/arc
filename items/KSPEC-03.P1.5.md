---
id: "KSPEC-03.P1.5"
title: "M20 identity disposition on legacy receipts; reserve `receipt_context`"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["KSPEC-03.P1.4", "CT-WIRE.1"]
paths: ["crates/kernel/chio-kernel/src/kernel/identity_disposition.rs", "crates/kernel/chio-kernel/src/kernel/responses/deny_responses.rs", "spec/schemas/chio-wire/v1/receipt/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-2 (KSPEC-03 phase 1: KDEF-D1, N2, N28, N29, together with the M20 identity-disposition delta; one train batch because KSPEC-08 rule S15 ties `retryable_after_resume` to M20). Spec: `docs/superpowers/specs/2026-10-04-typed-reservations-design.md` (KSPEC-03). No `IdentityDisposition` exists anywhere today; `chio_runtime` is already reserved (`RESERVED_RECEIPT_METADATA_KEYS`, `kernel/mod.rs:155-165`) but `receipt_context` is not. Add the M20 disposition to every non-allow legacy receipt and reserve `receipt_context`. Wire-visible: append to the receipt schema under the CT-WIRE freeze rules (new field, no byte change to frozen fields). The reserved-key list edit in `kernel/mod.rs` is a one-line change; KSPEC-08.P1.10 follows this item in the same file.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Table-driven test: every non-allow legacy receipt carries the disposition M20 assigns; caller metadata containing `receipt_context` is rejected.

## Log
- 2026-10-09T04:51:58Z connor: created
