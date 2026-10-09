---
id: "UR-U3.5"
title: "Complete the ADR index and record reserved ADR numbers"
severity: "P1"
wave: 1
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: ["DOCS-1177.2"]
paths: ["docs/adr/README.md", "docs/README.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 2.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: U3, section 9 ("The ADR indexes: they stop at ADR-0020 and ADR-0021"). On post-#1160 main `docs/adr/README.md` lists ADR-0001 to ADR-0021 but `ADR-0022-store-and-kernel-decomposition.md` exists. Add ADR-0022, keep the ADR-0038 entry from DOCS-1177.2, and add a "Reserved numbers" note: ADR-0023 to ADR-0037 are candidates proposed in #1170 (`docs/research/nvidia/06-strategy-and-roadmap.md` section 12) and are not yet written; ADR-0035 (web3-free distribution) and ADR-0036 (receipt privacy) are referenced by this roadmap. Note that ADR-0018 numbering collides with ADR-0018 proposals in #1029 and `research/genesis-program` (roadmap section 7): any surviving content is renumbered. Update the ADR section of `docs/README.md` if it has its own list.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Every `docs/adr/ADR-*.md` file is listed exactly once in `docs/adr/README.md` (a one-line shell check in the commit body proves it).
- The reserved-number note lists ADR-0023 to ADR-0037 as candidates and names the ADR-0018 collision.

## Log
- 2026-10-09T04:51:58Z connor: created
