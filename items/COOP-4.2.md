---
id: "COOP-4.2"
title: "MCP edge authorization audit (north-star bet 8)"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["REL-2.3", "REL-2.0"]
paths: ["docs/security/audits/mcp-authorization-2026-07-28.md", "crates/protocol/chio-mcp-remote/tests/mcp_authorization_audit.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-4 ("evidence a counterparty can trust without trusting the operator"; claims stay labelled "signatures verified against pinned keys; no external witness" until witnessing exists). Bet 8 (north-star doc lines 247-262): audit audience validation, no token passthrough, per-client consent on the MCP door under revision 2026-07-28. Findings become tests; fixes beyond test-level go to follow-up notes.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- The audit doc lists each control with a test; `cargo test -p chio-mcp-remote --test mcp_authorization_audit` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
