---
id: "UR-U3.3"
title: "Remove and scope uniqueness claims in COMPETITIVE_LANDSCAPE and flagship docs"
severity: "P1"
wave: 1
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: ["DOCS-1177.1"]
paths: ["docs/reference/COMPETITIVE_LANDSCAPE.md", "docs/start-here/FLAGSHIP_WALL_STOPS_MONEY.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 3.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: U3, section 9. `docs/reference/COMPETITIVE_LANDSCAPE.md:527` says "Chio is the only protocol where ..." (post-#1160 line). Replace every uniqueness claim with the scoped form from section 9: no shipped product combines all four of separately operated owners who each admit at their own door, attenuation-only grants, evidence the counterparty verifies offline, and durable work identity. Note that "agent OS" and "agent kernel" are crowded labels (another vendor calls its toolkit "the kernel for AI agents"); never use "kernel" as the category for platform audiences. Also fix the "only protocol" claim in `docs/start-here/FLAGSHIP_WALL_STOPS_MONEY.md` (listed in #1177's restructure file map).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `git grep -n -i "only protocol" -- docs/reference docs/start-here` returns nothing.
- `python3 scripts/check-native-host-docs.py --rule retired-phrases` passes for both files.

## Log
- 2026-10-09T04:51:58Z connor: created
