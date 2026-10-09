---
id: "REL-2.0"
title: "MCP 2026-07-28 interop research note (stateless core) against the current edge"
severity: "P1"
wave: 1
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["docs/research/mcp-2026-07-28-interop.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 5.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: REL-2, G0.4 ("MCP interop research (REL-2)" starts without waiting for Gate 0). The edge accepts only protocol revision 2025-11-25 today: `crates/protocol/chio-mcp-edge/src/runtime.rs:92` (`MCP_PROTOCOL_VERSION`), `crates/protocol/chio-mcp-adapter/src/transport/utils.rs:16`, `crates/products/chio-cli/src/cli/mcp/wrap.rs:28`, `crates/platform/chio-agent-web-interop/src/protocols.rs:62`, `crates/platform/chio-control-plane/src/certify/artifact.rs:316,335`. Write a note that diffs MCP revision 2026-07-28 (stateless core) against 2025-11-25 from the published specification, lists every Chio code site affected (initialize/version negotiation, session lifecycle in `crates/protocol/chio-mcp-remote/src/remote_mcp/session_core.rs`, request handling in `crates/protocol/chio-mcp-edge/src/runtime/`), and states what current Claude Code and Codex releases send when connecting to an ordinary remote MCP server. Output: a site-by-site change list that REL-2.1 and REL-2.2 implement.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- The note lists every `2025-11-25` occurrence on main (`git grep -n 2025-11-25 -- crates`) with its required change.
- Each harness behaviour claim cites the harness version and source (release notes or captured traffic).

## Log
- 2026-10-09T04:51:58Z connor: created
