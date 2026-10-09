---
id: "REL-2.2"
title: "`chio mcp serve-http` stateless mode for 2026-07-28 clients"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["REL-2.1"]
paths: ["crates/protocol/chio-mcp-remote/src/remote_mcp/session_core.rs", "crates/protocol/chio-mcp-remote/src/remote_mcp/http_service.rs", "crates/protocol/chio-mcp-remote/src/remote_mcp/hosted_tests/stateless.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: REL-2. `chio mcp serve-http` is implemented in `crates/protocol/chio-mcp-remote` (re-exported by `crates/protocol/chio-hosted-mcp/src/lib.rs` as `serve_http`). Its sessions assume the 2025-11-25 lifecycle (`crates/protocol/chio-mcp-remote/src/remote_mcp/session_core.rs`). Add the stateless request path so a 2026-07-28 client can call tools without session initialization, while every call still runs kernel admission and produces a receipt. Session isolation guarantees for 2025-11-25 clients must not regress (`hosted_tests/session_isolation.rs`). Note: KSPEC-05 Part A (KERN-4) later reworks this session door; keep the change minimal and documented so KERN-4 can absorb it.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `crates/protocol/chio-mcp-remote/src/remote_mcp/hosted_tests/stateless.rs`: stateless allow with receipt, stateless deny with receipt, stateless request cannot read another session's state.
- `cargo test -p chio-mcp-remote hosted_tests` passes (existing session tests unchanged).

## Log
- 2026-10-09T04:51:58Z connor: created
