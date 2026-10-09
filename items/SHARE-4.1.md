---
id: "SHARE-4.1"
title: "Accept ADR-0016 (authoritative spend contract)"
severity: "P1"
wave: 1
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["docs/adr/ADR-0016-authoritative-spend-contract.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 2.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: SHARE-4, section 8 "Recorded, not open: accept ADR-0016"; G3's `prevent` claim is `ready_after_adr (ADR-0016, CT-ABI)`. `docs/adr/ADR-0016-authoritative-spend-contract.md` is `Status: Proposed`. Change it to Accepted with the decision date of the roadmap approval (2026-10-08, owner-set), add a short "Acceptance" section that links SHARE-1 (one consumption ledger) as the implementing lane, and leave the decision text unchanged.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- ADR-0016 header says Accepted and links the roadmap; no other ADR text changes (`git diff --stat` shows one file, small diff).

## Log
- 2026-10-09T04:51:58Z connor: created
