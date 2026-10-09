---
id: "SHARE-3.5"
title: "Add Pi and Hermes to the HOST-M2 root grant"
severity: "P2"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["SHARE-3.1", "REL-3.4"]
paths: ["crates/products/chio-cli/tests/process_host/root_grant_pi_hermes.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: SHARE-3 ("then Pi and Hermes"), D12 recommendation (Pi and Hermes as additional HOST-M2 harnesses). Extend the shared root grant to sessions launched through the Pi and Hermes Linux launchers (REL-3.4). Not a G3 exit requirement; G3 requires Claude Code and Codex.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `root_grant_pi_hermes.rs` proves all four harness kinds draw from one family hold on one Linux host.

## Log
- 2026-10-09T04:51:58Z connor: created
