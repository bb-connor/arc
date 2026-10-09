---
id: "KSPEC-05.A.1"
title: "Per-request response slots, causal identity, session-side finish_call (A1-A4, KDEF-D3)"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["REL-2.3"]
paths: ["crates/protocol/chio-mcp-remote/src/remote_mcp/http_service.rs", "crates/protocol/chio-mcp-remote/src/remote_mcp/session_core/session.rs", "crates/protocol/chio-mcp-remote/src/remote_mcp/session_core/writer.rs", "crates/protocol/chio-mcp-remote/src/remote_mcp/session_credentials.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 16.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-4 (KSPEC-05 Part A: KDEF-D3, D4, N26; N30 is already fixed on #1160), because doors serve over `chio mcp serve-http`. Spec: `docs/superpowers/specs/2026-10-04-unified-event-queue-design.md` (KSPEC-05). Note REL-2.2 added a stateless path in the same files; keep it working. On #1160, POST lag closes the session (`http_service.rs:572-578`) and initialize lag returns 503 (`:667-676`): the hang is gone but lag now costs the whole session. Add per-request slots so lag affects one request.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Capacity-8 streaming without `chioRequestId` is delivered exactly once; a credential session ends `completed_unacknowledged`; JSON-RPC id reuse handled; `cargo test -p chio-mcp-remote slots` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
