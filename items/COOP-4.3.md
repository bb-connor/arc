---
id: "COOP-4.3"
title: "Claim labelling on every COOP evidence output"
severity: "P1"
wave: 2
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: ["OUT-4.2"]
paths: ["crates/platform/chio-control-plane/src/evidence_export/claim_label.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 4.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-4 ("evidence a counterparty can trust without trusting the operator"; claims stay labelled "signatures verified against pinned keys; no external witness" until witnessing exists). Every COOP output (evidence verify, partner card verify, door receipts) prints its `boundary_class` and the label "signatures verified against pinned keys; no external witness". Implement as a small module used by `evidence_export.rs` (one call-site edit around lines 474-532, after COOP-1.7).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `evidence_verify_prints_claim_label` passes; the label text matches `docs/records/gate-claims.yaml`.

## Log
- 2026-10-09T04:51:58Z connor: created
