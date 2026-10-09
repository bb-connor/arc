---
id: "CT-CROSS.3"
title: "iroh lane relay posture: self-hosted relays only for federation lanes"
severity: "P1"
wave: 1
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-CROSS.1"]
paths: ["docs/adr/ADR-0014-iroh-federation-transport.md", "crates/products/chio-cli/src/cli/chio/dispatch/pheromone/iroh_mount.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: CT-CROSS, D4 (iroh stays an optional lane with self-hosted relays), U9, section 10 (n0's free public iroh relays end 2026-12-31; ADR-0014 line 458). Record the self-hosted relay requirement in ADR-0014 and make federation lanes refuse n0 default relays unless explicitly configured (relay mode is configurable in `iroh_mount.rs:1115`). The `iroh` feature is default-off in `chio-cli`.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-cli --features iroh iroh_mount::relay_mode` covers refusal of default relays and acceptance of an explicit self-hosted relay.

## Log
- 2026-10-09T04:51:58Z connor: created
