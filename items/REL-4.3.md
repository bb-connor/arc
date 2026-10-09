---
id: "REL-4.3"
title: "Dashboard issuance panel over the COOP-1 issuance inbox"
severity: "P1"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["REL-4.1", "COOP-1.4a"]
paths: ["crates/products/chio-cli/dashboard/src/components/Issuance*.tsx", "crates/products/chio-cli/dashboard/src/types.ts"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: REL-4 ("the issuance panel"), G2 steps 3 and 4 (inbox, holder pickup). Show the issuance inbox (pending requests, issued capabilities awaiting holder pickup, picked up, expired) using the routes COOP-1.1 adds, with approve and reject actions gated by the approver principal. The panel never displays capability secrets; pickup is holder-authenticated (COOP-1.2).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Component tests cover each inbox state and that no token material is rendered.
- A manual walkthrough script (`dashboard/scripts/issuance-walkthrough.md` or test) is referenced in the PR.

## Log
- 2026-10-09T04:51:58Z connor: created
