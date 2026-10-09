---
id: "KSPEC-05.A.4b"
title: "Ongoing subscription authority and expiry (A30, A31)"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["KSPEC-05.A.4a"]
paths: ["crates/protocol/chio-mcp-remote/src/remote_mcp/session_core.rs", "crates/protocol/chio-mcp-remote/src/remote_mcp/session_resume.rs", "crates/protocol/chio-mcp-remote/src/remote_mcp/session_recovery.rs", "crates/protocol/chio-mcp-remote/src/remote_mcp/session_store.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-4 (KSPEC-05 Part A: KDEF-D3, D4, N26; N30 is already fixed on #1160), because doors serve over `chio mcp serve-http`. Spec: `docs/superpowers/specs/2026-10-04-unified-event-queue-design.md` (KSPEC-05). Note REL-2.2 added a stateless path in the same files; keep it working. Standard authority must remain live with Part B disabled.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- "standard authority remains live with Part B disabled" passes; expired authority stops delivery with a receipt.

## Log
- 2026-10-09T04:51:58Z connor: created
