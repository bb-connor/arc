---
id: "KSPEC-07.S1"
title: "Adapted-server native_launch binding (KDEF-N3) and PROTOCOL section 6 disclosure"
severity: "P2"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["KSPEC-07.AMEND", "REL-2.1"]
paths: ["crates/protocol/chio-mcp-adapter/src/server.rs", "crates/protocol/chio-mcp-adapter/src/transport/**", "crates/tooling/chio-conformance/tests/threats/tool_server_escape.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-5 (KSPEC-07 steps 1 and 2, plus `AgentHostBwrap` and `Seatbelt` backend kinds, before any HOST-M2 isolation claim). Spec: `docs/superpowers/specs/2026-10-04-microkernel-isolation-backend-design.md` (KSPEC-07). `AdaptedMcpServer` (`crates/protocol/chio-mcp-adapter/src/server.rs:141`) exposes `native_enforcement_receipt` but does not override `prepared_native_launch_receipt` (default at `crates/kernel/chio-kernel/src/runtime/connection.rs:185`). Bind it. Update the `spec/PROTOCOL.md` section 6 disclosure table through a small edit after UR-U3.4 (header item) has landed.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- An adapted-server call carries `native_launch`; preparation errors after `Exited`; the disclosure table renders for every `ToolOrigin`.

## Log
- 2026-10-09T04:51:58Z connor: created
