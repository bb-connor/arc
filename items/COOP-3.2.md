---
id: "COOP-3.2"
title: "Receiver-owned admission hook on `chio mcp serve-http`"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["COOP-3.1", "REL-2.3"]
paths: ["crates/protocol/chio-mcp-remote/src/remote_mcp/admission_profile.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-3 ("the HOST-M3 door"), G4/G5 claim "the receiver admits a co-signed work commitment at its own door" (`prevent`, `ready_after_adr` CT-WORK, CT-CROSS); success-test criterion (b). Same hook and receiver-signed profile as COOP-3.1 for the MCP door (doors serve over `chio mcp serve-http`).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- serve-http denies a federated call without a treaty and admits one within it, each with a receipt (`cargo test -p chio-mcp-remote admission_profile`).

## Log
- 2026-10-09T04:51:58Z connor: created
