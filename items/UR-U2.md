---
id: "UR-U2"
title: "Rewrite Clawdstrike material in the #1177 set as a prior-art note"
severity: "P1"
wave: 1
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: ["DOCS-1177.0"]
paths: ["docs/superpowers/specs/2026-10-07-macos-integration/research/clawdstrike.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 3.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: U2, rule 5 ("Clawdstrike is prior art, not a peer"), recorded decision "STRAT-F17 void". Rewrite `docs/superpowers/specs/2026-10-07-macos-integration/research/clawdstrike.md` as a prior-art note: its Linux observation work (Tetragon, Hubble) and its macOS Endpoint Security and Network Extension plumbing are source material Chio absorbs into its own crates and host adapters. It is never an integration target, a boundary, an owner or a peer. Then grep the rest of the imported #1177 set (`git grep -n -i clawdstrike -- docs/superpowers`) and list any peer framing found outside this file in the commit body; files other than clawdstrike.md belong to DOCS-1177.5 to DOCS-1177.7 and are fixed there (add a checklist line to those items' PRs rather than editing them here, to keep path leases disjoint). The #1170 half of U2 is parked with #1170 (D15).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- clawdstrike.md contains no "peer", "partner", "integration target" or "owner" framing for Clawdstrike; it names Tetragon, Hubble, Endpoint Security and Network Extension as absorbed source material.
- The commit body lists every other Clawdstrike mention in the #1177 set with the item that owns its fix.

## Log
- 2026-10-09T04:51:58Z connor: created
