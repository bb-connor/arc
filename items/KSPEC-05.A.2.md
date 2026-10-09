---
id: "KSPEC-05.A.2"
title: "Lag resync (A7-A11) replacing close-on-lag"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["KSPEC-05.A.1"]
paths: ["crates/protocol/chio-mcp-remote/src/remote_mcp/http_service.rs", "crates/protocol/chio-mcp-remote/src/remote_mcp/session_core/session.rs", "spec/WIRE_PROTOCOL.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-4 (KSPEC-05 Part A: KDEF-D3, D4, N26; N30 is already fixed on #1160), because doors serve over `chio mcp serve-http`. Spec: `docs/superpowers/specs/2026-10-04-unified-event-queue-design.md` (KSPEC-05). Note REL-2.2 added a stateless path in the same files; keep it working. Resync with complete cursors; document the wire behaviour in `spec/WIRE_PROTOCOL.md`.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- "resync routing and complete cursors (A7/A8)" test passes.

## Log
- 2026-10-09T04:51:58Z connor: created
